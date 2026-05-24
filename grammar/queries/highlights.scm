(package_clause "package" @keyword)
(import_declaration "import" @keyword)
(type_declaration "type" @keyword)
(function_declaration "func" @keyword)
(map_declaration "map" @keyword)
(attribute "@" @attribute)
(string_literal) @string
(number_literal) @number
(bool_literal) @constant.builtin
(identifier) @variable
