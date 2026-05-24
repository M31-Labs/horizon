(package_clause
  name: (identifier) @name) @definition.package

(import_declaration
  alias: (identifier) @name) @definition.import

(const_declaration
  name: (identifier) @name) @definition.constant

(function_declaration
  name: (identifier) @name) @definition.function

(type_declaration
  name: (identifier) @name) @definition.type

(field_declaration
  name: (identifier) @name) @definition.field

(map_declaration
  name: (identifier) @name) @definition.map

(attribute
  name: (identifier) @name) @definition.attribute
