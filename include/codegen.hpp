#pragma once

#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/StandardInstrumentations.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Transforms/Scalar/Reassociate.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"

#include <map>

#include "ast.hpp"
#include <typeindex>

namespace wl {

class CodegenContext {
  std::unique_ptr<llvm::LLVMContext> m_context;
  std::unique_ptr<llvm::Module> m_module;
  std::unique_ptr<llvm::IRBuilder<>> m_builder;
  std::unordered_map<std::string, llvm::AllocaInst*> m_named_values;
  std::unordered_map<std::string, llvm::Function *> m_functions;

  std::unique_ptr<llvm::FunctionPassManager> m_FPM;
  std::unique_ptr<llvm::LoopAnalysisManager> m_LAM;
  std::unique_ptr<llvm::FunctionAnalysisManager> m_FAM;
  std::unique_ptr<llvm::CGSCCAnalysisManager> m_CGAM;
  std::unique_ptr<llvm::ModuleAnalysisManager> m_MAM;
  std::unique_ptr<llvm::PassInstrumentationCallbacks> m_PIC;
  std::unique_ptr<llvm::StandardInstrumentations> m_SI;

  std::unique_ptr<llvm::Function> m_top_level_function;

  std::size_t m_next_id;
public:
  CodegenContext();
  llvm::Value *codegen(const ExpAST &exp);
  void codegen(const StmtAST &stmt);

  double codegen_top_level(const StmtAST &exp);
private:
  llvm::Value *codegen_VarAST(const VarAST &var);
  llvm::Value *codegen_NumConstAST(const NumConstAST &num);
  llvm::Value *codegen_UnaryExpAST(const UnaryExpAST &exp);
  llvm::Value *codegen_BinaryExpAST(const BinaryExpAST &exp);
  llvm::Value *codegen_CallAST(const CallAST &call);
  void codegen_AsgnStmtAST(const AsgnStmtAST &stmt);
  void codegen_SkipStmtAST(const SkipStmtAST &stmt);
  void codegen_SeqStmtAST(const SeqStmtAST &stmt);
  void codegen_IfStmtAST(const IfStmtAST &stmt);
  void codegen_WhileStmtAST(const WhileStmtAST &stmt);
  void codegen_FuncDefAST(const FuncDefAST &func);

  llvm::AllocaInst *create_entry_block_alloca(llvm::Function *function, const std::string &name);
  std::size_t get_next_id();
  std::string get_next_tag(std::string prefix);
};

struct CodegenError : public std::runtime_error {
  CodegenError(const std::string &msg = "");
};

}