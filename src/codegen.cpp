#include "ast.hpp"
#include "codegen.hpp"
#include "KaleidoscopeJIT.h"

using llvm::Value;
using llvm::ConstantFP;
using llvm::LLVMContext;
using llvm::APFloat;
using llvm::Function;
using llvm::FunctionType;
using llvm::Type;
using llvm::IRBuilder;
using llvm::BasicBlock;
using llvm::Module;
using llvm::PHINode;
using llvm::AllocaInst;
using llvm::verifyFunction;

using llvm::FunctionPassManager;
using llvm::LoopAnalysisManager;
using llvm::FunctionAnalysisManager;
using llvm::CGSCCAnalysisManager;
using llvm::ModuleAnalysisManager;
using llvm::PassInstrumentationCallbacks;
using llvm::StandardInstrumentations;

using llvm::InstCombinePass;
using llvm::ReassociatePass;
using llvm::GVNPass;
using llvm::SimplifyCFGPass;

using llvm::PassBuilder;

using llvm::orc::ThreadSafeModule;
using llvm::ExitOnError;

namespace wl {

static std::unique_ptr<llvm::orc::KaleidoscopeJIT> s_JIT;

CodegenError::CodegenError(const std::string &msg) : std::runtime_error(msg) {}

CodegenContext::CodegenContext() :
  m_context(std::make_unique<LLVMContext>()),
  m_module(std::make_unique<Module>("while_lang_JIT", *m_context)),
  m_builder(std::make_unique<IRBuilder<>>(*m_context)),
  m_top_level_function(
    Function::Create(
      FunctionType::get(
        Type::getDoubleTy(*m_context), {}, false),
      Function::ExternalLinkage,
      "<module>",
      *m_module)),
  m_FPM(std::make_unique<FunctionPassManager>()),
  m_LAM(std::make_unique<LoopAnalysisManager>()),
  m_FAM(std::make_unique<FunctionAnalysisManager>()),
  m_CGAM(std::make_unique<CGSCCAnalysisManager>()),
  m_MAM(std::make_unique<ModuleAnalysisManager>()),
  m_PIC(std::make_unique<PassInstrumentationCallbacks>()),
  m_SI(std::make_unique<StandardInstrumentations>(*m_context, true)),
  m_named_values({}),
  m_functions({}),
  m_next_id(0) {
  std::cerr << "Before CodegenContext{} " << std::endl;
    auto maybe_JIT = llvm::orc::KaleidoscopeJIT::Create();
  std::cerr << "After JIT Create " << std::endl;
    if (!maybe_JIT) {
  std::cerr << "After JIT Create error " << std::endl;
      auto err = maybe_JIT.takeError();
      auto err_msg = llvm::toString(std::move(err));
      std::cerr << "Failed to create KaleidoscopeJIT: " << err_msg << std::endl;
      throw CodegenError("Failed to create KaleidoscopeJIT");
    }
  std::cerr << "After JIT Create2 " << std::endl;
    s_JIT = maybe_JIT.operator bool() ? std::move(maybe_JIT.get()) : nullptr;
    if (!s_JIT) {
      throw CodegenError("Failed to create KaleidoscopeJIT");
    }
  std::cerr << "After JIT " << std::endl;

    m_module->setDataLayout(s_JIT->getDataLayout());

    m_SI->registerCallbacks(*m_PIC, m_MAM.get());

    m_FPM->addPass(InstCombinePass());
    m_FPM->addPass(ReassociatePass());
    m_FPM->addPass(GVNPass());
    m_FPM->addPass(SimplifyCFGPass());

    PassBuilder PB;
    PB.registerModuleAnalyses(*m_MAM);
    PB.registerFunctionAnalyses(*m_FAM);
    PB.crossRegisterProxies(*m_LAM, *m_FAM, *m_CGAM, *m_MAM);
  }

Value *CodegenContext::codegen_VarAST(const VarAST &var) {
  auto var_name = var.get_name();
  auto a = m_named_values[var_name];
  if (!a) {
    Function *function = m_builder->GetInsertBlock()->getParent();
    a = create_entry_block_alloca(function, var_name);
    m_named_values[var_name] = a;
    Value *zero = ConstantFP::get(*m_context, APFloat(0.0));
    m_builder->CreateStore(zero, a);
  }
  return m_builder->CreateLoad(a->getAllocatedType(), a, var.get_name());
}

Value *CodegenContext::codegen_NumConstAST(const NumConstAST &num) {
  return ConstantFP::get(*m_context, APFloat(num.get_value()));
}

Value *CodegenContext::codegen_UnaryExpAST(const UnaryExpAST &exp) {
  auto rhs = codegen(*exp.get_rhs());
  switch (exp.get_op()) {
    case Keyword::Kind::Not:
      return m_builder->CreateNot(rhs, "not");
    default:
      throw CodegenError("codegen: Unknown unary operator");
  }
}

Value *CodegenContext::codegen_BinaryExpAST(const BinaryExpAST &exp) {
  auto lhs = codegen(*exp.get_lhs());
  auto rhs = codegen(*exp.get_rhs());
  switch (exp.get_op()) {
  case Keyword::Kind::And:
    return m_builder->CreateAnd(lhs, rhs, "and");
  case Keyword::Kind::Or:
    return m_builder->CreateOr(lhs, rhs, "or");
  case Keyword::Kind::Lt:
    return m_builder->CreateFCmpULT(lhs, rhs, "lt");
  case Keyword::Kind::Le:
    return m_builder->CreateFCmpULE(lhs, rhs, "le");
  case Keyword::Kind::Gt:
    return m_builder->CreateFCmpUGT(lhs, rhs, "gt");
  case Keyword::Kind::Ge:
    return m_builder->CreateFCmpUGE(lhs, rhs, "ge");
  case Keyword::Kind::Eq:
    return m_builder->CreateFCmpOEQ(lhs, rhs, "eq");
  case Keyword::Kind::Neq:
    return m_builder->CreateFCmpUNE(lhs, rhs, "neq");
  case Keyword::Kind::Plus:
    return m_builder->CreateFAdd(lhs, rhs, "plus");
  case Keyword::Kind::Minus:
    return m_builder->CreateFSub(lhs, rhs, "minus");
  case Keyword::Kind::Mul:
    return m_builder->CreateFMul(lhs, rhs, "mul");
  case Keyword::Kind::Div:
    return m_builder->CreateFDiv(lhs, rhs, "div");
  case Keyword::Kind::Mod:
    return m_builder->CreateFRem(lhs, rhs, "mod");
  default:
    throw CodegenError("Codegen: Unknown binary operator");
  }
}

Value *CodegenContext::codegen_CallAST(const CallAST &call) {
  auto function_name = call.get_name();
  auto &&args = call.get_args();
  auto fp = m_functions.find(function_name);
  if (fp == m_functions.end()) {
    throw CodegenError("Codegen: Unknown function " + function_name);
  }
  auto function = fp->second;

  if (function->arg_size() != args.size()) {
    throw CodegenError("Codegen: Function " + function_name + " takes " +
                       std::to_string(function->arg_size()) + " arguments, " +
                       std::to_string(args.size()) + " given");
  }
  std::vector<Value *> arg_values;
  for (auto &arg : args) {
    arg_values.push_back(codegen(*arg));
  }
  return m_builder->CreateCall(function, arg_values, "call");
}

AllocaInst *CodegenContext::create_entry_block_alloca(Function *function, const std::string &name) {
  IRBuilder<> temp_builder(&function->getEntryBlock(),
                    function->getEntryBlock().begin());
  return temp_builder.CreateAlloca(Type::getDoubleTy(*m_context), nullptr, name);
}

size_t CodegenContext::get_next_id() {
  return m_next_id++;
}

std::string CodegenContext::get_next_tag(std::string prefix) {
  return prefix + std::to_string(get_next_id());
}

void CodegenContext::codegen_AsgnStmtAST(const AsgnStmtAST &stmt) {
  auto var_name = stmt.get_lhs()->get_name();
  AllocaInst *a = m_named_values[var_name];
  if (!a) {
    Function *function = m_builder->GetInsertBlock()->getParent();
    a = create_entry_block_alloca(function, var_name);
    m_named_values[var_name] = a;
  }
  Value *rhs = codegen(*stmt.get_rhs());
  m_builder->CreateStore(rhs, a);
}

void CodegenContext::codegen_SkipStmtAST(const SkipStmtAST &stmt) {
}

void CodegenContext::codegen_SeqStmtAST(const SeqStmtAST &stmt) {
  codegen(*stmt.get_lhs());
  codegen(*stmt.get_rhs());
}

void CodegenContext::codegen_IfStmtAST(const IfStmtAST &stmt) {
  auto ifcond_name = get_next_tag("ifcond");
  auto iftrue_name = get_next_tag("iftrue");
  auto iffalse_name = get_next_tag("iffalse");
  auto ifmerge_name = get_next_tag("ifmerge");

  Value *cond = codegen(*stmt.get_cond());
  cond = m_builder->CreateFCmpONE(cond, ConstantFP::get(*m_context, APFloat(0.0)), ifcond_name);

  Function *function = m_builder->GetInsertBlock()->getParent();

  BasicBlock *if_true = BasicBlock::Create(*m_context, iftrue_name, function);
  BasicBlock *if_false = BasicBlock::Create(*m_context, iffalse_name);
  BasicBlock *if_merge = BasicBlock::Create(*m_context, ifmerge_name);

  m_builder->CreateCondBr(cond, if_true, if_false);

  // true branch
  m_builder->SetInsertPoint(if_true);
  codegen(*stmt.get_then_stmt());
  m_builder->CreateBr(if_merge);
  if_true = m_builder->GetInsertBlock();

  // false branch
  function->insert(function->end(), if_false);
  m_builder->SetInsertPoint(if_false);
  codegen(*stmt.get_else_stmt());
  m_builder->CreateBr(if_merge);
  if_false = m_builder->GetInsertBlock();

  // merge
  function->insert(function->end(), if_merge);
  m_builder->SetInsertPoint(if_merge);
}

void CodegenContext::codegen_WhileStmtAST(const WhileStmtAST &stmt) {
  auto whilecond_name = get_next_tag("whilecond");
  auto whiletrue_name = get_next_tag("whiletrue");
  auto whilemerge_name = get_next_tag("whilemerge");

  Function *function = m_builder->GetInsertBlock()->getParent();

  BasicBlock *while_cond = BasicBlock::Create(*m_context, whilecond_name, function);
  BasicBlock *while_true = BasicBlock::Create(*m_context, whiletrue_name);
  BasicBlock *while_merge = BasicBlock::Create(*m_context, whilemerge_name);

  // cond
  m_builder->SetInsertPoint(while_cond);
  Value *cond = codegen(*stmt.get_cond());
  cond = m_builder->CreateFCmpONE(cond, ConstantFP::get(*m_context, APFloat(0.0)), whilecond_name);
  m_builder->CreateCondBr(cond, while_true, while_merge);
  while_cond = m_builder->GetInsertBlock();

  // true
  function->insert(function->end(), while_true);
  m_builder->SetInsertPoint(while_true);
  codegen(*stmt.get_stmt());
  m_builder->CreateBr(while_cond);
  while_true = m_builder->GetInsertBlock();

  // merge
  function->insert(function->end(), while_merge);
  m_builder->SetInsertPoint(while_merge);
}

void CodegenContext::codegen_FuncDefAST(const FuncDefAST &func) {
  std::vector<Type *> arg_types(func.get_params().size(), Type::getDoubleTy(*m_context));
  FunctionType *func_type = FunctionType::get(Type::getDoubleTy(*m_context), arg_types, false);

  auto func_name = func.get_name();
  auto prev_fp = m_functions.find(func_name);
  Function *function = nullptr;
  if (prev_fp != m_functions.end()) {
    function = prev_fp->second;
    if (!(function->getFunctionType() == func_type)) {
      throw ParserError("Type mismatch in function '" + func_name + "'");
    }
    if (!function->empty()) {
      throw ParserError("Function '" + func_name + "' is already defined");
    }
  } else {
    function = Function::Create(func_type, Function::ExternalLinkage, func_name, *m_module);

    size_t i = 0;
    for (auto &arg : function->args()) {
      arg.setName(func.get_params()[i++]);
    }
    // add to map before generating body so that it can be referenced
    m_functions[func_name] = function;
  }

  auto maybe_body = func.get_body();
  if (!maybe_body) {
    return;
  }

  BasicBlock *block = BasicBlock::Create(*m_context, "entry", function);
  m_builder->SetInsertPoint(block);

  // store named values
  auto prev_named_values = std::move(m_named_values);
  assert(m_named_values.empty());

  for (auto &arg : function->args()) {
    AllocaInst *a = create_entry_block_alloca(function, arg.getName().str());
    m_builder->CreateStore(&arg, a);
    m_named_values[arg.getName().str()] = a;
  }
  AllocaInst *ret = create_entry_block_alloca(function, "ret");
  m_builder->CreateStore(ConstantFP::get(*m_context, APFloat(0.0)), ret);
  m_named_values["ret"] = ret;

  codegen(*maybe_body);

  Value *ret_value = m_builder->CreateLoad(Type::getDoubleTy(*m_context), ret, "ret");
  m_builder->CreateRet(ret_value);

  // restore named values
  m_named_values = std::move(prev_named_values);

  auto failed = verifyFunction(*function, &llvm::errs());

  if (failed) {
    function->eraseFromParent();
    throw CodegenError("Codegen: failed to verify function");
  }

}

Value *CodegenContext::codegen(const ExpAST &exp) {
  if (auto t = dynamic_cast<const VarAST*>(&exp)) {
    return codegen_VarAST(*t);
  } else if (auto t = dynamic_cast<const NumConstAST*>(&exp)) {
    return codegen_NumConstAST(*t);
  } else if (auto t = dynamic_cast<const UnaryExpAST*>(&exp)) {
    return codegen_UnaryExpAST(*t);
  } else if (auto t = dynamic_cast<const BinaryExpAST*>(&exp)) {
    return codegen_BinaryExpAST(*t);
  } else if (auto t = dynamic_cast<const CallAST*>(&exp)) {
    return codegen_CallAST(*t);
  } else {
    throw CodegenError("Codegen: unknown expression or statement type");
  }
}

void CodegenContext::codegen(const StmtAST &stmt) {
  if (auto t = dynamic_cast<const AsgnStmtAST*>(&stmt)) {
    return codegen_AsgnStmtAST(*t);
  } else if (auto t = dynamic_cast<const SkipStmtAST*>(&stmt)) {
    return codegen_SkipStmtAST(*t);
  } else if (auto t = dynamic_cast<const SeqStmtAST*>(&stmt)) {
    return codegen_SeqStmtAST(*t);
  } else if (auto t = dynamic_cast<const IfStmtAST*>(&stmt)) {
    return codegen_IfStmtAST(*t);
  } else if (auto t = dynamic_cast<const WhileStmtAST*>(&stmt)) {
    return codegen_WhileStmtAST(*t);
  } else if (auto t = dynamic_cast<const FuncDefAST*>(&stmt)) {
    return codegen_FuncDefAST(*t);
  } else {
    throw CodegenError("Codegen: unknown expression or statement type");
  }
}

double CodegenContext::codegen_top_level(const StmtAST &exp) {
  std::cerr << "Before codegen: " << std::endl;
  codegen(exp);

  std::cerr << "After codegen: " << std::endl;
  auto RT = s_JIT->getMainJITDylib().createResourceTracker();
  auto TSM = llvm::orc::ThreadSafeModule(std::move(m_module), std::move(m_context));
  auto error = s_JIT->addModule(std::move(TSM), RT);
  auto expr_symbol = s_JIT->lookup("<module>").get();
  std::cerr << "Before entry: " << std::endl;
  double (*fp)() = expr_symbol.getAddress().toPtr<double (*)()>();
  std::cerr << "After entry. " << std::endl;
  std::cerr << "Entry: " << fp << std::endl;

  if (!fp) {
    return -42.0;
  }
  auto result = fp();
  return result;
}

}