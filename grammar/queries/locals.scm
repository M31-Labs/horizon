(source_file) @local.scope

(block) @local.scope

(function_declaration
  name: (identifier) @local.definition.function)

(type_declaration
  name: (identifier) @local.definition.type)

(const_declaration
  name: (identifier) @local.definition.constant)

(parameter
  name: (identifier) @local.definition.parameter)

(map_declaration
  name: (identifier) @local.definition.map)

(short_var_declaration
  name: (identifier) @local.definition.var)

(import_declaration
  alias: (identifier) @local.definition.namespace)

(identifier) @local.reference
