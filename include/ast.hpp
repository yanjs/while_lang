#pragma once

#include <string>
#include <memory>
#include <variant>
#include <vector>
#include <stdexcept>
#include <unordered_set>
#include <map>
#include "lexer.hpp"

namespace wl {

template <typename T>
using ptr = std::unique_ptr<T>;
template <typename T>
using vec = std::vector<T>;
template <typename T>
using set = std::unordered_set<T>;
using str = std::string;
using sv = std::string_view;
using kind = Keyword::Kind;

class FuncDefAST;

class State {
  std::map<str, double> m_variables;
  std::map<str, const FuncDefAST*> m_functions;
public:
  double operator[](const str& name) const;
  double& operator[](const str& name);
  void add_function(const FuncDefAST* f);
  const FuncDefAST* get_function(const str& name) const;

  void print() const;
};

class IAST {
public:
  virtual ~IAST() = default;
  virtual set<str> get_vars() const = 0;
};

class ExpAST: public IAST {
public:
  virtual ~ExpAST() = default;
  virtual double eval(const State&) const = 0;
};

class VarAST: public ExpAST {
  str name;
public:
  VarAST(const str& n);
  virtual set<str> get_vars() const override;
  virtual double eval(const State&) const override;
  str get_name() const;
};

class NumConstAST: public ExpAST {
  double value;
public:
  NumConstAST(double v);
  virtual set<str> get_vars() const override;
  virtual double eval(const State&) const override;
};

class UnaryExpAST: public ExpAST {
  kind op;
  ptr<ExpAST> rhs;
public:
  UnaryExpAST(kind o, ptr<ExpAST> r);
  virtual set<str> get_vars() const override;
  virtual double eval(const State&) const override;
};

class BinaryExpAST: public ExpAST {
  kind op;
  ptr<ExpAST> lhs;
  ptr<ExpAST> rhs;
public:
  BinaryExpAST(kind o, ptr<ExpAST> l, ptr<ExpAST> r);
  virtual set<str> get_vars() const override;
  virtual double eval(const State&) const override;
};

class CallAST: public ExpAST {
  str name;
  vec<ptr<ExpAST>> args;
public:
  CallAST(const str& n, vec<ptr<ExpAST>> a);
  virtual set<str> get_vars() const override;
  virtual double eval(const State&) const override;
};


class StmtAST: public IAST {
public:
  virtual ~StmtAST() = default;
  virtual State& run(State&) const = 0;
};

class AsgnStmtAST: public StmtAST {
  ptr<VarAST> var;
  ptr<ExpAST> expr;
public:
  AsgnStmtAST(ptr<VarAST> v, ptr<ExpAST> e);
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
};

class SkipStmtAST: public StmtAST {
public:
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
};

class SeqStmtAST : public StmtAST {
  ptr<StmtAST> lhs;
  ptr<StmtAST> rhs;
public:
  SeqStmtAST(ptr<StmtAST> l, ptr<StmtAST> r);
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
};

class IfStmtAST : public StmtAST {
  ptr<ExpAST> cond;
  ptr<StmtAST> then_stmt;
  ptr<StmtAST> else_stmt;
public:
  IfStmtAST(ptr<ExpAST> c, ptr<StmtAST> t, ptr<StmtAST> e);
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
};

class WhileStmtAST : public StmtAST {
  ptr<ExpAST> cond;
  ptr<StmtAST> stmt;
public:
  WhileStmtAST(ptr<ExpAST> c, ptr<StmtAST> b);
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
};

class FuncDefAST: public StmtAST {
  str name;
  vec<str> params;
  ptr<StmtAST> body;
public:
  FuncDefAST(str n, vec<str> p, ptr<StmtAST> b);
  virtual set<str> get_vars() const override;
  virtual State& run(State&) const override;
  str get_name() const;
  const vec<str>& get_params() const;
  const StmtAST* get_body() const;
};

struct ParserError: std::runtime_error {
  ParserError(const std::string& what = "");
};

static std::unique_ptr<ExpAST> parse_paren_exp(Lexer &lexer);
static std::unique_ptr<ExpAST> parse_single_exp(Lexer &lexer);
static std::unique_ptr<ExpAST> parse_exp(Lexer &lexer);
static std::unique_ptr<StmtAST> parse_if_stmt(Lexer &lexer);
static std::unique_ptr<StmtAST> parse_while_stmt(Lexer &lexer);
static std::unique_ptr<StmtAST> parse_single_stmt(Lexer &lexer);
std::unique_ptr<StmtAST> parse_stmt(Lexer &lexer);

} // namespace wl