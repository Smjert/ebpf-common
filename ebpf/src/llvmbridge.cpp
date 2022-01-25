//
// Copyright (c) 2021-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

#include "llvmbridge.h"

#include <btfparse/ibtf.h>
#include <llvm/IR/DerivedTypes.h>
#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpf {

namespace {

const std::unordered_map<BTFKind, std::optional<LLVMBridgeError> (*)(
                                      LLVMBridge::Context &, llvm::Module &,
                                      std::uint32_t, const BTFType &)>
    kBTFTypeImporterMap = {
        {BTFKind::Void, LLVMBridge::skipType},
        {BTFKind::Int, LLVMBridge::importIntType},
        {BTFKind::Ptr, LLVMBridge::importPtrType},
        {BTFKind::Array, LLVMBridge::importArrayType},
        {BTFKind::Struct, LLVMBridge::importStructType},
        {BTFKind::Union, LLVMBridge::importUnionType},
        {BTFKind::Enum, LLVMBridge::importEnumType},
        {BTFKind::Fwd, LLVMBridge::importFwdType},
        {BTFKind::Typedef, LLVMBridge::importTypedefType},
        {BTFKind::Volatile, LLVMBridge::importVolatileType},
        {BTFKind::Const, LLVMBridge::importConstType},
        {BTFKind::Restrict, LLVMBridge::importRestrictType},
        {BTFKind::Func, LLVMBridge::skipType},
        {BTFKind::FuncProto, LLVMBridge::importFuncProtoType},
        {BTFKind::Var, LLVMBridge::skipType},
        {BTFKind::DataSec, LLVMBridge::skipType},
        {BTFKind::Float, LLVMBridge::importFloatType},
};

} // namespace

LLVMBridge::LLVMBridge(llvm::Module &module, const IBTF &btf)
    : d(new Context(module)) {

  d->btf_type_map = btf.getAll();

  auto opt_error = importAllTypes();
  if (opt_error.has_value()) {
    throw opt_error.value();
  }
}

LLVMBridge::~LLVMBridge() {}

Result<llvm::Type *, LLVMBridgeError>
LLVMBridge::getType(const std::string &name) const {
  return getType(*d.get(), name);
}

struct Index final {
  std::uint32_t value{};
  std::uint32_t type{};
  bool is_union{false};
};

using IndexList = std::vector<Index>;

std::optional<IndexList> locateHelper(IndexList index_list,
                                      const BTFTypeMap &btf_type_map,
                                      std::uint32_t btf_type_id,
                                      const std::string &component);

template <typename StructOrUnion>
std::optional<IndexList>
locateHelper(IndexList index_list, const BTFTypeMap &btf_type_map,
             const StructOrUnion &obj, const std::string &component) {

  const auto &member_list = obj.member_list;

  auto is_union = std::is_same<StructOrUnion, UnionBTFType>::value;

  for (auto member_it = member_list.begin(); member_it != member_list.end();
       ++member_it) {

    const auto &member = *member_it;
    auto member_index = static_cast<std::uint32_t>(
        std::distance(member_list.begin(), member_it));

    if (member.opt_name.has_value()) {
      const auto &name = member.opt_name.value();

      if (name == component) {
        index_list.push_back({member_index, member.type, is_union});
        return index_list;
      }

    } else {
      auto new_index_list = index_list;
      new_index_list.push_back({member_index, member.type, is_union});

      auto opt_index_list =
          locateHelper(new_index_list, btf_type_map, member.type, component);

      if (opt_index_list.has_value()) {
        return opt_index_list;
      }
    }
  }

  return std::nullopt;
}

std::optional<IndexList> locateHelper(IndexList index_list,
                                      const BTFTypeMap &btf_type_map,
                                      std::uint32_t btf_type_id,
                                      const std::string &component) {

  auto btf_type_it = btf_type_map.find(btf_type_id);
  if (btf_type_it == btf_type_map.end()) {
    return std::nullopt;
  }

  const auto &btf_type = btf_type_it->second;

  if (std::holds_alternative<StructBTFType>(btf_type)) {
    const auto &obj = std::get<StructBTFType>(btf_type);
    return locateHelper(index_list, btf_type_map, obj, component);

  } else if (std::holds_alternative<UnionBTFType>(btf_type)) {
    const auto &obj = std::get<UnionBTFType>(btf_type);
    return locateHelper(index_list, btf_type_map, obj, component);
  }

  return std::nullopt;
}

std::optional<IndexList> locate(const BTFTypeMap &btf_type_map,
                                std::uint32_t btf_type_id,
                                const std::string &component) {

  return locateHelper({}, btf_type_map, btf_type_id, component);
}

std::optional<LLVMBridgeError>
LLVMBridge::read(llvm::IRBuilder<> &builder, llvm::Value *dest,
                 llvm::Value *src, const std::string &path,
                 llvm::BasicBlock *read_succeeded,
                 llvm::BasicBlock *read_failed) const {
  auto component_list = tokenizePath(path);
  if (component_list.empty()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructurePath);
  }

  auto pointer_type = src->getType();
  if (!pointer_type->isPointerTy()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::NotAStructPointer);
  }

  auto pointee_type = pointer_type->getPointerElementType();

  auto llvm_struct_type = llvm::dyn_cast<llvm::StructType>(pointee_type);
  if (llvm_struct_type == nullptr) {
    return LLVMBridgeError(LLVMBridgeErrorCode::NotAStructPointer);
  }

  auto btf_type_id_it = d->llvm_to_btf_type_id.find(llvm_struct_type);
  if (btf_type_id_it == d->llvm_to_btf_type_id.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::TypeIsNotIndexed);
  }

  auto pointer = builder.CreateGEP(src, builder.getInt32(0));
  auto btf_type_id = btf_type_id_it->second;

  for (const auto &component : component_list) {
    auto opt_index_list = locate(d->btf_type_map, btf_type_id, component);
    if (!opt_index_list.has_value()) {
      return std::nullopt;
    }

    const auto &index_list = opt_index_list.value();

    auto L_getName = [](const std::string &name,
                        std::uint32_t btf_type) -> std::string {
      return name + "_of_type_" + std::to_string(btf_type) + "___";
    };

    for (const auto &index : index_list) {
      btf_type_id = index.type;

      if (index.is_union) {
        pointer = builder.CreateGEP(pointer,
                                    {builder.getInt32(0), builder.getInt32(0)},
                                    L_getName("union_data", btf_type_id));

        auto union_field_type = d->btf_type_id_to_llvm.at(btf_type_id);

        pointer =
            builder.CreateBitCast(pointer, union_field_type->getPointerTo(),
                                  L_getName("casted_union_data", btf_type_id));

        continue;
      }

      auto llvm_index = index.value;
      auto struct_mapping_it = d->btf_struct_mapping.find(btf_type_id);
      if (struct_mapping_it != d->btf_struct_mapping.end()) {
        const auto &struct_mapping = struct_mapping_it->second;

        llvm_index = static_cast<std::uint32_t>(
            struct_mapping[index.value].llvm_member_index);
      }

      pointer = builder.CreateGEP(
          pointer, {builder.getInt32(0), builder.getInt32(llvm_index)},
          L_getName("struct_field", btf_type_id));
    }
  }

  auto syscall_interface_exp = BPFSyscallInterface::create(builder);
  if (!syscall_interface_exp.succeeded()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InternalError);
  }

  auto syscall_interface = syscall_interface_exp.takeValue();

  auto current_bb = builder.GetInsertBlock();
  auto &module = *current_bb->getModule();

  auto dest_size =
      static_cast<std::uint32_t>(ebpf::getTypeSize(module, dest->getType()));

  auto read_status =
      syscall_interface->probeRead(dest, builder.getInt64(dest_size), pointer);

  auto cond = builder.CreateICmpEQ(builder.getInt64(0U), read_status);

  builder.CreateCondBr(cond, read_succeeded, read_failed);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importAllTypes() {
  // Initialize the type queue
  std::vector<std::uint32_t> next_id_queue(d->btf_type_map.size());

  std::size_t i{};
  for (const auto &btf_type_p : d->btf_type_map) {
    next_id_queue[i] = btf_type_p.first;
    ++i;
  }

  // BTF id 0 is never defined, and is interpreted as the `void` type
  auto &llvm_context = d->module.getContext();
  auto void_type = llvm::Type::getVoidTy(llvm_context);

  d->btf_type_id_to_llvm.insert({0, void_type});
  d->llvm_to_btf_type_id.insert({void_type, 0});

  // Attempt to import types in a loop until there are no new updates
  while (!next_id_queue.empty()) {
    auto current_id_queue = std::move(next_id_queue);
    next_id_queue.clear();

    bool updated{false};

    for (const auto &id : current_id_queue) {
      const auto &btf_type = d->btf_type_map.at(id);

      // In case we fail with a `MissingDependency` error, put this
      // type back into the queue so that we'll try again to import it
      // later
      auto opt_error = importType(id, btf_type);
      if (opt_error.has_value()) {
        auto error = opt_error.value();
        if (error.get() != LLVMBridgeErrorCode::MissingDependency) {
          return error;
        }

        next_id_queue.push_back(id);

      } else {
        updated = true;
      }
    }

    if (!updated) {
      break;
    }
  }

  // If the next queue is not empty, we have failed to import one or
  // more types
  if (!next_id_queue.empty()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importType(std::uint32_t id,
                                                      const BTFType &type) {
  auto importer_it = kBTFTypeImporterMap.find(IBTF::getBTFTypeKind(type));
  if (importer_it == kBTFTypeImporterMap.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  const auto &importer = importer_it->second;
  return importer(*d.get(), d->module, id, type);
}

Result<llvm::Type *, LLVMBridgeError>
LLVMBridge::getType(const Context &context, const std::string &name) {
  auto btf_type_id_it = context.name_to_btf_type_id.find(name);
  if (btf_type_id_it == context.name_to_btf_type_id.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::NotFound);
  }

  auto btf_type_id = btf_type_id_it->second;

  auto llvm_type_it = context.btf_type_id_to_llvm.find(btf_type_id);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::TypeIsNotIndexed);
  }

  return llvm_type_it->second;
}

std::vector<std::string> LLVMBridge::tokenizePath(const std::string &path) {
  std::vector<std::string> string_list;

  std::size_t start{};

  while (start < path.size()) {
    auto end = path.find_first_of('.', start);
    if (end == std::string::npos) {
      end = path.size();
    }

    auto str = path.substr(start, end - start);
    string_list.push_back(std::move(str));

    start = end + 1;
  }

  return string_list;
}

llvm::StructType *LLVMBridge::getOrCreateOpaqueStruct(
    Context &context, llvm::Module &module, std::uint32_t id,
    const std::optional<std::string> &opt_name) {
  llvm::StructType *llvm_struct_type{nullptr};

  auto llvm_type_it = context.btf_type_id_to_llvm.find(id);
  if (llvm_type_it != context.btf_type_id_to_llvm.end()) {
    llvm_struct_type = static_cast<llvm::StructType *>(llvm_type_it->second);

  } else {
    auto &llvm_context = module.getContext();

    if (opt_name.has_value()) {
      llvm_struct_type =
          llvm::StructType::create(llvm_context, opt_name.value());
    } else {
      llvm_struct_type = llvm::StructType::create(llvm_context);
    }

    saveType(context, id, llvm_struct_type, opt_name);
  }

  return llvm_struct_type;
}

void LLVMBridge::saveType(Context &context, std::uint32_t id, llvm::Type *type,
                          const std::optional<std::string> &opt_name) {
  context.btf_type_id_to_llvm.insert({id, type});
  context.llvm_to_btf_type_id.insert({type, id});

  if (opt_name.has_value()) {
    const auto &name = opt_name.value();

    if (context.blocked_type_name_list.count(name) != 0) {
      return;
    }

    if (context.name_to_btf_type_id.count(name) > 0) {
      context.blocked_type_name_list.insert(name);
      context.name_to_btf_type_id.erase(name);

    } else {
      context.name_to_btf_type_id.insert({name, id});
    }
  }
}

std::optional<LLVMBridgeError> LLVMBridge::skipType(Context &, llvm::Module &,
                                                    std::uint32_t,
                                                    const BTFType &) {
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importIntType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  llvm::Type *llvm_type{nullptr};

  const auto &int_type = std::get<IntBTFType>(type);
  switch (int_type.size) {
  case 1:
    llvm_type = llvm::Type::getInt8Ty(llvm_context);
    break;

  case 2:
    llvm_type = llvm::Type::getInt16Ty(llvm_context);
    break;

  case 4:
    llvm_type = llvm::Type::getInt32Ty(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getInt64Ty(llvm_context);
    break;

  case 16:
    llvm_type = llvm::Type::getInt128Ty(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importPtrType(Context &context,
                                                         llvm::Module &,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &ptr_type = std::get<PtrBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(ptr_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto base_llvm_type = llvm_type_it->second;
  auto llvm_type = base_llvm_type->getPointerTo();

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importArrayType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &array_type = std::get<ArrayBTFType>(type);

  auto llvm_elem_type_it = context.btf_type_id_to_llvm.find(array_type.type);
  if (llvm_elem_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_elem_type = llvm_elem_type_it->second;
  auto llvm_type = llvm::ArrayType::get(llvm_elem_type, array_type.nelems);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importStructType(Context &context, llvm::Module &module,
                             std::uint32_t id, const BTFType &type) {
  const auto &struct_type = std::get<StructBTFType>(type);

  auto llvm_struct_type =
      getOrCreateOpaqueStruct(context, module, id, struct_type.opt_name);

  if (!llvm_struct_type->isOpaque()) {
    return std::nullopt;
  }

  const auto &member_list = struct_type.member_list;
  auto bitfield_list_res =
      collapseBitfieldMembers(context, module, member_list, struct_type.size);

  if (bitfield_list_res.failed()) {
    return bitfield_list_res.takeError();
  }

  auto bitfield_list = bitfield_list_res.takeValue();
  auto &llvm_context = module.getContext();

  std::vector<llvm::Type *> llvm_type_list;
  std::uint32_t current_offset{};

  Context::StructMapping struct_mapping;

  for (std::size_t member_index = 0; member_index < member_list.size();
       ++member_index) {

    const auto &member = member_list.at(member_index);

    auto member_offset = member.offset / 8;
    if ((member.offset % 8) != 0) {
      return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructureMemberOffset);
    }

    if (member_offset < current_offset) {
      return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructureMemberOffset);
    }

    auto padding_byte_count = member_offset - current_offset;
    if (padding_byte_count != 0) {
      auto byte_type = llvm::Type::getInt8Ty(llvm_context);
      auto padding_type = llvm::ArrayType::get(byte_type, padding_byte_count);
      llvm_type_list.push_back(padding_type);
    }

    auto bitfield_it =
        std::find_if(bitfield_list.begin(), bitfield_list.end(),
                     [member_index](const Bitfield &bitfield) {
                       return member_index == bitfield.start_index;
                     });

    if (bitfield_it != bitfield_list.end()) {
      const auto &bitfield = *bitfield_it;

      auto byte_type = llvm::Type::getInt8Ty(llvm_context);
      auto bitfield_storage =
          llvm::ArrayType::get(byte_type, bitfield.byte_size);

      llvm_type_list.push_back(bitfield_storage);

      for (std::size_t bitfield_part_index{};
           bitfield_part_index < bitfield.member_count; ++bitfield_part_index) {

        const auto &bitfield_member =
            member_list.at(member_index + bitfield_part_index);

        Context::FieldIndex::Mask mask;
        mask.bit_offset = bitfield_member.offset;
        mask.bit_size = bitfield_member.opt_bitfield_size.value();

        Context::FieldIndex field_index;
        field_index.llvm_member_index = llvm_type_list.size();
        field_index.opt_mask = std::move(mask);

        struct_mapping.push_back(std::move(field_index));
      }

      current_offset += bitfield.byte_size;
      member_index += bitfield.member_count - 1;

    } else {
      auto llvm_member_type_it = context.btf_type_id_to_llvm.find(member.type);
      if (llvm_member_type_it == context.btf_type_id_to_llvm.end()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
      }

      struct_mapping.push_back({llvm_type_list.size(), std::nullopt});

      auto llvm_member_type = llvm_member_type_it->second;
      llvm_type_list.push_back(llvm_member_type);

      if (!llvm_member_type->isSized()) {
        return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
      }

      auto member_size =
          static_cast<std::uint32_t>(getTypeSize(module, llvm_member_type));

      current_offset = member_offset + member_size;
    }
  }

  auto padding_byte_count = struct_type.size - current_offset;
  if (padding_byte_count != 0) {
    auto byte_type = llvm::Type::getInt8Ty(llvm_context);
    auto padding_type = llvm::ArrayType::get(byte_type, padding_byte_count);
    llvm_type_list.push_back(padding_type);

    current_offset += padding_byte_count;
  }

  context.btf_struct_mapping.insert({id, struct_mapping});
  llvm_struct_type->setBody(llvm_type_list, true);

  auto final_size =
      static_cast<std::uint32_t>(getTypeSize(module, llvm_struct_type));

  if (current_offset != struct_type.size || final_size != struct_type.size) {
    return LLVMBridgeError(LLVMBridgeErrorCode::InvalidStructSize);
  }

  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importUnionType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  const auto &union_type = std::get<UnionBTFType>(type);

  auto llvm_struct_type =
      getOrCreateOpaqueStruct(context, module, id, union_type.opt_name);

  if (!llvm_struct_type->isOpaque()) {
    return std::nullopt;
  }

  std::uint32_t union_size{};

  for (const auto &member : union_type.member_list) {
    auto llvm_member_type_it = context.btf_type_id_to_llvm.find(member.type);
    if (llvm_member_type_it == context.btf_type_id_to_llvm.end()) {
      return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
    }

    auto llvm_member_type = llvm_member_type_it->second;
    if (!llvm_member_type->isSized()) {
      return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
    }

    auto member_size =
        static_cast<std::uint32_t>(getTypeSize(module, llvm_member_type));

    union_size = std::max(union_size, member_size);
  }

  auto &llvm_context = module.getContext();
  auto byte_type = llvm::Type::getInt8Ty(llvm_context);

  std::vector<llvm::Type *> llvm_type_list{
      llvm::ArrayType::get(byte_type, union_size)};

  llvm_struct_type->setBody(llvm_type_list, true);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importEnumType(Context &context,
                                                          llvm::Module &module,
                                                          std::uint32_t id,
                                                          const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  const auto &enum_type = std::get<EnumBTFType>(type);

  llvm::Type *llvm_type{nullptr};

  switch (enum_type.size) {
  case 1:
    llvm_type = llvm::Type::getInt8Ty(llvm_context);
    break;

  case 2:
    llvm_type = llvm::Type::getInt16Ty(llvm_context);
    break;

  case 4:
    llvm_type = llvm::Type::getInt32Ty(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getInt64Ty(llvm_context);
    break;

  case 16:
    llvm_type = llvm::Type::getInt128Ty(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError> LLVMBridge::importFwdType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  auto &llvm_context = module.getContext();
  auto llvm_type = llvm::StructType::get(llvm_context);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importTypedefType(Context &context, llvm::Module &module,
                              std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &typedef_type = std::get<TypedefBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(typedef_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, typedef_type.name);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importVolatileType(Context &context, llvm::Module &module,
                               std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &volatile_type = std::get<VolatileBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(volatile_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importRestrictType(Context &context, llvm::Module &module,
                               std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &restrict_type = std::get<RestrictBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(restrict_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importConstType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &const_type = std::get<ConstBTFType>(type);

  auto llvm_type_it = context.btf_type_id_to_llvm.find(const_type.type);
  if (llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto llvm_type = llvm_type_it->second;

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importFuncProtoType(Context &context, llvm::Module &module,
                                std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  std::vector<llvm::Type *> param_type_list;

  const auto &func_proto_type = std::get<FuncProtoBTFType>(type);
  for (const auto &param : func_proto_type.param_list) {
    auto param_llvm_type_it = context.btf_type_id_to_llvm.find(param.type);
    if (param_llvm_type_it == context.btf_type_id_to_llvm.end()) {
      return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
    }

    auto param_llvm_type = param_llvm_type_it->second;
    param_type_list.push_back(param_llvm_type);
  }

  auto return_llvm_type_it =
      context.btf_type_id_to_llvm.find(func_proto_type.return_type);

  if (return_llvm_type_it == context.btf_type_id_to_llvm.end()) {
    return LLVMBridgeError(LLVMBridgeErrorCode::MissingDependency);
  }

  auto return_llvm_type = return_llvm_type_it->second;

  auto llvm_type = llvm::FunctionType::get(return_llvm_type, param_type_list,
                                           func_proto_type.is_variadic);

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

std::optional<LLVMBridgeError>
LLVMBridge::importFloatType(Context &context, llvm::Module &module,
                            std::uint32_t id, const BTFType &type) {
  if (context.btf_type_id_to_llvm.count(id) > 0) {
    return std::nullopt;
  }

  const auto &float_type = std::get<FloatBTFType>(type);

  auto &llvm_context = module.getContext();
  llvm::Type *llvm_type{nullptr};

  switch (float_type.size) {
  case 4:
    llvm_type = llvm::Type::getFloatTy(llvm_context);
    break;

  case 8:
    llvm_type = llvm::Type::getDoubleTy(llvm_context);
    break;

  default:
    return LLVMBridgeError(LLVMBridgeErrorCode::UnsupportedBTFType);
  }

  saveType(context, id, llvm_type, std::nullopt);
  return std::nullopt;
}

Result<LLVMBridge::BitfieldList, LLVMBridgeError>
LLVMBridge::collapseBitfieldMembers(
    const Context &context, llvm::Module &llvm_module,
    const StructBTFType::MemberList &member_list, std::size_t struct_size) {

  BitfieldList bitfield_list;
  std::optional<Bitfield> opt_bitfield;

  auto L_saveBitfield = [&bitfield_list, &opt_bitfield, &member_list,
                         struct_size](std::size_t end_index) {
    auto &bitfield = opt_bitfield.value();
    bitfield.member_count = (end_index - bitfield.start_index) + 1;

    const auto &start_member = member_list.at(bitfield.start_index);
    const auto &last_member = member_list.at(end_index);

    bitfield.bit_size =
        (last_member.offset + last_member.opt_bitfield_size.value()) -
        start_member.offset;

    auto next_index = end_index + 1;
    if (next_index >= member_list.size()) {
      bitfield.byte_size = struct_size;
    } else {
      const auto &next_member = member_list.at(next_index);
      bitfield.byte_size = (next_member.offset - start_member.offset) / 8;
    }

    bitfield_list.push_back(std::move(bitfield));
    opt_bitfield = std::nullopt;
  };

  for (std::size_t member_index{0}; member_index < member_list.size();
       ++member_index) {
    const auto &member = member_list.at(member_index);

    auto inside_active_bitfield = opt_bitfield.has_value();
    auto member_is_bitfield = member.opt_bitfield_size.has_value() &&
                              member.opt_bitfield_size.value() != 0;

    if (inside_active_bitfield != member_is_bitfield) {
      if (inside_active_bitfield) {
        L_saveBitfield(member_index - 1);

      } else {
        Bitfield bitfield;
        bitfield.start_index = member_index;

        opt_bitfield = std::move(bitfield);
      }
    }
  }

  if (opt_bitfield.has_value()) {
    L_saveBitfield(member_list.size() - 1);
  }

  return bitfield_list;
}

} // namespace tob::ebpf
