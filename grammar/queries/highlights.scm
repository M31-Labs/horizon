(package_clause "package" @keyword)
(import_declaration "import" @keyword)
(type_declaration "type" @keyword)
(const_declaration "const" @keyword)
(function_declaration "func" @keyword)
(map_declaration "map" @keyword)
(struct_type "struct" @keyword)
(return_statement "return" @keyword)
(if_statement "if" @keyword)
(if_statement "else" @keyword)
(for_statement "for" @keyword)

(attribute
  "@" @punctuation.special
  name: (identifier) @attribute)

(line_comment) @comment
(string_literal) @string
(number_literal) @number
(bool_literal) @constant.builtin
(nil_literal) @constant.builtin

(function_declaration
  name: (identifier) @function)

(call_expression
  function: (identifier) @function)

(call_expression
  function: (selector_expression
    operand: (identifier) @namespace
    field: (identifier) @function.method))

(selector_expression
  operand: (identifier) @namespace
  field: (identifier) @property)

(type_declaration
  name: (identifier) @type)

(struct_type
  (field_declaration
    name: (identifier) @property))

(literal_field
  name: (identifier) @property)

(map_declaration
  name: (identifier) @variable)

(const_declaration
  name: (identifier) @constant)

(parameter
  name: (identifier) @variable.parameter)

(import_declaration
  alias: (identifier) @namespace)

(binary_expression
  operator: (_) @operator)

(condition_binary_expression
  operator: (_) @operator)

(unary_expression
  operator: (_) @operator)

(condition_unary_expression
  operator: (_) @operator)

(identifier) @variable
