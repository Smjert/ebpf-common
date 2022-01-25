//
// Copyright (c) 2021-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

#pragma once

#include <optional>
#include <unordered_map>
#include <unordered_set>

#include <tob/ebpf/illvmbridge.h>

namespace tob::ebpf {

class LLVMBridge final : public ILLVMBridge {
public:
  LLVMBridge(llvm::Module &module, const IBTF &btf);
  virtual ~LLVMBridge();

  virtual Result<llvm::Type *, LLVMBridgeError>
  getType(const std::string &name) const override;

  virtual std::optional<LLVMBridgeError>
  read(llvm::IRBuilder<> &builder, llvm::Value *dest, llvm::Value *src,
       const std::string &path, llvm::BasicBlock *read_succeeded,
       llvm::BasicBlock *read_failed) const override;

private:
  std::optional<LLVMBridgeError> importAllTypes();
  std::optional<LLVMBridgeError> importType(std::uint32_t id,
                                            const BTFType &type);

public:
  struct Context final {
    Context(llvm::Module &module_) : module(module_) {}

    /// All the types that have been imported by BTF
    BTFTypeMap btf_type_map;

    /// Maps a C structure/union field to a storage
    struct FieldIndex final {
      /// A mask used to extract the value, used for bitfields
      struct Mask final {
        /// A bit offset into the bitfield
        std::uint32_t bit_offset{};

        /// The value size, in bits
        std::uint32_t bit_size{};
      };

      /// An optional mask, used for bitfields
      using OptionalMask = std::optional<Mask>;

      /// LLVM struct index
      std::size_t llvm_member_index{};

      /// An optional mask, used for bitfields
      OptionalMask opt_mask;
    };

    /// Maps a BTF struct or union to an LLVM struct type
    using StructMapping = std::vector<FieldIndex>;

    /// The LLVM module where types are imported
    llvm::Module &module;

    /// Maps a type name to the BTF id
    std::unordered_map<std::string, std::uint32_t> name_to_btf_type_id;

    /// Prevents different types with the same name from becoming public
    std::unordered_set<std::string> blocked_type_name_list;

    /// Maps a BTF struct type ID to its LLVM mapping information
    std::unordered_map<std::uint32_t, StructMapping> btf_struct_mapping;

    /// BTF type ID to LLVM type
    std::unordered_map<std::uint32_t, llvm::Type *> btf_type_id_to_llvm;

    /// LLVM type to BTF type ID
    std::unordered_map<llvm::Type *, std::uint32_t> llvm_to_btf_type_id;
  };

  std::unique_ptr<Context> d;

  static Result<llvm::Type *, LLVMBridgeError> getType(const Context &context,
                                                       const std::string &name);

  static std::vector<std::string> tokenizePath(const std::string &path);

  static llvm::StructType *
  getOrCreateOpaqueStruct(Context &context, llvm::Module &module,
                          std::uint32_t id,
                          const std::optional<std::string> &opt_name);

  static void saveType(Context &context, std::uint32_t id, llvm::Type *type,
                       const std::optional<std::string> &opt_name);

  static std::optional<LLVMBridgeError> skipType(Context &context,
                                                 llvm::Module &module,
                                                 std::uint32_t id,
                                                 const BTFType &type);

  static std::optional<LLVMBridgeError> importIntType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  static std::optional<LLVMBridgeError> importPtrType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  static std::optional<LLVMBridgeError> importArrayType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  static std::optional<LLVMBridgeError> importStructType(Context &context,
                                                         llvm::Module &module,
                                                         std::uint32_t id,
                                                         const BTFType &type);

  static std::optional<LLVMBridgeError> importUnionType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  static std::optional<LLVMBridgeError> importEnumType(Context &context,
                                                       llvm::Module &module,
                                                       std::uint32_t id,
                                                       const BTFType &type);

  static std::optional<LLVMBridgeError> importFwdType(Context &context,
                                                      llvm::Module &module,
                                                      std::uint32_t id,
                                                      const BTFType &type);

  static std::optional<LLVMBridgeError> importTypedefType(Context &context,
                                                          llvm::Module &module,
                                                          std::uint32_t id,
                                                          const BTFType &type);

  static std::optional<LLVMBridgeError> importVolatileType(Context &context,
                                                           llvm::Module &module,
                                                           std::uint32_t id,
                                                           const BTFType &type);

  static std::optional<LLVMBridgeError> importRestrictType(Context &context,
                                                           llvm::Module &module,
                                                           std::uint32_t id,
                                                           const BTFType &type);

  static std::optional<LLVMBridgeError> importConstType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  static std::optional<LLVMBridgeError>
  importFuncProtoType(Context &context, llvm::Module &module, std::uint32_t id,
                      const BTFType &type);

  static std::optional<LLVMBridgeError> importFloatType(Context &context,
                                                        llvm::Module &module,
                                                        std::uint32_t id,
                                                        const BTFType &type);

  struct Bitfield final {
    std::size_t start_index{};
    std::size_t member_count{};
    std::size_t bit_size{};
    std::size_t byte_size{};
  };

  using BitfieldList = std::vector<Bitfield>;

  static Result<LLVMBridge::BitfieldList, LLVMBridgeError>
  collapseBitfieldMembers(const Context &context, llvm::Module &llvm_module,
                          const StructBTFType::MemberList &member_list,
                          std::size_t struct_size);
};

} // namespace tob::ebpf
