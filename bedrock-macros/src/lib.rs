use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, ImplItem, ImplItemFn, ItemImpl, Stmt,
    Variant, Visibility,
};

/// Procedural macro that enhances error enums with generic error handling
///
/// This macro automatically:
/// 1. Adds `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// 2. Adds a `Generic { message: String }` variant if not already present
/// 3. Implements `From<anyhow::Error>` for the error type
/// 4. Provides helper methods for error conversion
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_error]
/// pub enum MyError {
///     #[error("Specific error: {code}")]
///     SpecificError { code: u32 },
///     #[error("Another error: {message}")]
///     AnotherError { message: String },
/// }
/// ```
///
/// This will automatically add:
/// - `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// - `Generic { message: String }` variant
/// - `impl From<anyhow::Error> for MyError`
#[proc_macro_attribute]
pub fn bedrock_error(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded = match &input.data {
        Data::Enum(data_enum) => {
            let enum_name = &input.ident;
            let visibility = &input.vis;

            // Filter out any existing derive attributes to avoid duplicates
            let attrs: Vec<_> = input
                .attrs
                .iter()
                .filter(|attr| {
                    if attr.path().is_ident("derive") {
                        // Skip existing derive attributes to avoid conflicts
                        false
                    } else if attr.path().is_ident("uniffi") {
                        // Skip existing uniffi attributes to avoid conflicts
                        false
                    } else {
                        true
                    }
                })
                .collect();

            let generics = &input.generics;

            // Check if Generic variant already exists
            let has_generic = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "Generic");

            // Collect existing variants
            let mut variants = data_enum.variants.clone();

            // Add Generic variant if it doesn't exist
            if !has_generic {
                let generic_variant: Variant = syn::parse_quote! {
                    /// A generic error that can wrap any anyhow error.
                    #[error("Generic error: {message}")]
                    Generic {
                        /// The error message from the wrapped error.
                        message: String
                    }
                };
                variants.push(generic_variant);
            }

            // Generate the enhanced enum with automatic derives and attributes
            quote! {
                // Automatically import anyhow::Context for convenience
                use anyhow::Context;

                #[derive(Debug, thiserror::Error, uniffi::Error)]
                #[uniffi(flat_error)]
                #(#attrs)*
                #visibility enum #enum_name #generics {
                    #variants
                }

                impl #generics From<anyhow::Error> for #enum_name #generics {
                    fn from(err: anyhow::Error) -> Self {
                        Self::Generic {
                            message: {
                                // Include the full error chain in the message
                                let mut message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    message.push_str(" (caused by: ");
                                    message.push_str(&chain.join(" -> "));
                                    message.push(')');
                                }

                                message
                            }
                        }
                    }
                }

                impl #generics #enum_name #generics {
                    /// Convert an anyhow::Result to a Result with this error type
                    pub fn from_anyhow_result<T>(result: anyhow::Result<T>) -> Result<T, Self> {
                        result.map_err(Self::from)
                    }

                    /// Convert an anyhow::Result to a Result with this error type, adding a prefix
                    pub fn from_anyhow_result_with_prefix<T>(
                        result: anyhow::Result<T>,
                        prefix: &str
                    ) -> Result<T, Self> {
                        result.map_err(|err| Self::Generic {
                            message: {
                                // Format the error message directly without double prefixing
                                let mut message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    message.push_str(" (caused by: ");
                                    message.push_str(&chain.join(" -> "));
                                    message.push(')');
                                }

                                format!("{}: {}", prefix, message)
                            }
                        })
                    }
                }
            }
        }
        _ => {
            return syn::Error::new_spanned(
                &input,
                "bedrock_error can only be applied to enums",
            )
            .to_compile_error()
            .into();
        }
    };

    TokenStream::from(expanded)
}

/// Procedural macro that wraps `uniffi::export` and automatically injects logging context
///
/// This macro automatically:
/// 1. Forwards the attribute to `#[uniffi::export]`
/// 2. Injects `let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new("StructName");` at the start of every `pub fn`
/// 3. Extracts the struct/trait name from the impl block for context
/// 4. Automatically adds `async_runtime = "tokio"` if any async functions are detected
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_export]
/// impl MyStruct {
///     pub fn some_method(&self) -> String {
///         // _bedrock_logger_ctx is automatically injected here
///         debug!("This will be prefixed with [Bedrock][MyStruct]");
///         "result".to_string()
///     }
///     
///     pub async fn async_method(&self) -> String {
///         // async_runtime = "tokio" is automatically added to uniffi::export
///         "async result".to_string()
///     }
/// }
/// ```
///
/// This will automatically add logging context to all public methods in the impl block,
/// and tokio async runtime support if any async functions are present.
#[proc_macro_attribute]
pub fn bedrock_export(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_impl = parse_macro_input!(input as ItemImpl);

    // Extract the struct/trait name for logging context
    let type_name = match &*input_impl.self_ty {
        syn::Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                segment.ident.to_string()
            } else {
                "Unknown".to_string()
            }
        }
        _ => "Unknown".to_string(),
    };

    // Check if any public functions in the impl block are async
    let has_async_functions = has_async_functions_in_impl(&input_impl.items);

    // Process each method in the impl block
    let mut new_items = Vec::new();

    for item in &input_impl.items {
        match item {
            ImplItem::Fn(method) => {
                // Check if this is a public function
                if matches!(method.vis, Visibility::Public(_)) {
                    // Inject logging context at the start of the function body
                    let mut new_method = method.clone();
                    inject_logging_context(&mut new_method, &type_name);
                    new_items.push(ImplItem::Fn(new_method));
                } else {
                    // Keep private methods unchanged
                    new_items.push(item.clone());
                }
            }
            _ => {
                // Keep other items unchanged
                new_items.push(item.clone());
            }
        }
    }

    // Create the new impl block with modified methods
    let new_impl = ItemImpl {
        items: new_items,
        ..input_impl
    };

    // Generate the output with uniffi::export attribute
    let mut args = proc_macro2::TokenStream::from(args);

    // If we have async functions, add async_runtime = "tokio" to the attributes
    if has_async_functions {
        if args.is_empty() {
            // No existing args, just add the async_runtime
            args = quote! { async_runtime = "tokio" };
        } else {
            // Existing args, append the async_runtime
            args = quote! { #args, async_runtime = "tokio" };
        }
    }

    quote! {
        #[uniffi::export(#args)]
        #new_impl
    }
    .into()
}

/// Check if any public functions in the impl items are async
fn has_async_functions_in_impl(impl_items: &[ImplItem]) -> bool {
    impl_items.iter().any(|item| {
        if let ImplItem::Fn(method) = item {
            matches!(method.vis, Visibility::Public(_))
                && method.sig.asyncness.is_some()
        } else {
            false
        }
    })
}

/// Inject logging context at the start of a function body
fn inject_logging_context(method: &mut ImplItemFn, type_name: &str) {
    // Create the logging context statement
    let context_stmt: Stmt = syn::parse_quote! {
        let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new(#type_name);
    };

    // Insert at the beginning of the function body
    method.block.stmts.insert(0, context_stmt);
}

/// Procedural macro that wraps `alloy::sol!` and generates unparsed versions of structs
///
/// This macro:
/// 1. Forwards everything to `alloy::sol!`
/// 2. For structs listed in the `unparsed` attribute, generates:
///    - An `Unparsed{StructName}` struct with all String fields
///    - A `TryFrom<Unparsed{StructName}>` implementation
///
/// # Usage
///
/// ```rust,ignore
/// bedrock_sol! {
///     #[unparsed(TokenPermissions, PermitTransferFrom)]
///     
///     #[derive(serde::Serialize)]
///     struct TokenPermissions {
///         address token;
///         uint256 amount;
///     }
///     
///     #[derive(serde::Serialize)]
///     struct PermitTransferFrom {
///         TokenPermissions permitted;
///         address spender;
///         uint256 nonce;
///         uint256 deadline;
///     }
/// }
/// ```
///
/// This generates:
/// - The original sol! structs
/// - `UnparsedTokenPermissions` and `UnparsedPermitTransferFrom` structs
/// - `TryFrom` implementations for converting from unparsed to sol structs
#[proc_macro]
pub fn bedrock_sol(input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let lines = input_str.lines().collect::<Vec<_>>();

    // Find the #[unparsed(...)] attribute
    let mut unparsed_struct_names = Vec::new();
    let mut cleaned_lines = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check if this line contains #[unparsed(...)]
        if let Some(start) = line.find("#[unparsed(") {
            if let Some(end_bracket) = line[start..].find(")]") {
                let end = start + end_bracket;
                // Extract the attribute content
                let attr_start = start + "#[unparsed(".len();
                let content = &line[attr_start..end];

                unparsed_struct_names =
                    content.split(',').map(|s| s.trim().to_string()).collect();

                // Remove the attribute from the line
                let before = &line[..start];
                let after = if end + 2 < line.len() {
                    &line[end + 2..]
                } else {
                    ""
                };
                let cleaned_line = format!("{}{}", before, after);
                let cleaned_line = cleaned_line.trim();

                if !cleaned_line.is_empty() {
                    cleaned_lines.push(cleaned_line.to_string());
                }
                i += 1;
                continue;
            }
        }

        cleaned_lines.push(lines[i].to_string());
        i += 1;
    }

    // Parse all structs in the input
    let mut all_structs = Vec::new();
    let mut i = 0;

    // Convert cleaned_lines to &[&str] for parse_struct_definition
    let cleaned_lines_refs: Vec<&str> =
        cleaned_lines.iter().map(|s| s.as_str()).collect();

    while i < cleaned_lines_refs.len() {
        let line = cleaned_lines_refs[i].trim();

        if line.contains(" struct ") {
            if let Some(struct_info) = parse_struct_definition(&cleaned_lines_refs, i) {
                all_structs.push(struct_info);
            }
        }
        i += 1;
    }

    // Filter to only the structs that should have unparsed versions
    let unparsed_structs: Vec<_> = all_structs
        .iter()
        .filter(|s| unparsed_struct_names.contains(&s.name))
        .collect();

    // Generate the unparsed structs and TryFrom implementations
    let mut generated_code = String::new();

    for struct_info in &unparsed_structs {
        generated_code.push_str(&generate_unparsed_struct(struct_info));
        generated_code.push_str("\n\n");
        generated_code.push_str(&generate_try_from_impl(struct_info, &all_structs));
        generated_code.push_str("\n\n");
    }

    // Combine the cleaned sol! invocation with the generated code
    let output = format!(
        r#"
alloy::sol! {{
{}
}}

{}
"#,
        cleaned_lines.join("\n"),
        generated_code
    );

    output.parse().unwrap_or_else(|e| {
        panic!(
            "Failed to parse macro output: {}\nGenerated output:\n{}",
            e, output
        );
    })
}

#[derive(Debug)]
struct StructInfo {
    name: String,
    fields: Vec<FieldInfo>,
    doc_comments: Vec<String>,
}

#[derive(Debug)]
struct FieldInfo {
    name: String,
    ty: String,
    doc_comment: Option<String>,
}

fn parse_struct_definition(lines: &[&str], start_idx: usize) -> Option<StructInfo> {
    let struct_line = lines[start_idx].trim();

    // Find the struct keyword and extract the name
    let struct_pos = struct_line.find(" struct ")? + " struct ".len();
    let remaining = &struct_line[struct_pos..];
    let name = remaining
        .trim()
        .split_whitespace()
        .next()?
        .trim_end_matches('{')
        .to_string();

    // Collect doc comments before the struct
    let mut doc_comments = Vec::new();
    if start_idx > 0 {
        let mut idx = start_idx - 1;
        loop {
            let line = lines[idx].trim();
            if line.starts_with("///") {
                doc_comments.push(line.to_string());
                if idx == 0 {
                    break;
                }
                idx = idx.saturating_sub(1);
            } else if line.is_empty() {
                if idx == 0 {
                    break;
                }
                idx = idx.saturating_sub(1);
            } else {
                break;
            }
        }
        doc_comments.reverse();
    }

    // Parse fields
    let mut fields = Vec::new();

    // First check if the next line has the fields (common in sol! macros)
    if start_idx + 1 < lines.len() {
        let next_line = lines[start_idx + 1].trim();

        // Check if next line is a single-line field definition like "{ address token; uint256 amount; }"
        if next_line.starts_with('{') {
            if let Some(close_brace_pos) = next_line.find('}') {
                let content = &next_line[1..close_brace_pos];
                for field_str in content.split(';') {
                    let field_str = field_str.trim();
                    if field_str.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = field_str.split_whitespace().collect();
                    if parts.len() >= 2 {
                        fields.push(FieldInfo {
                            ty: parts[0].to_string(),
                            name: parts[1].to_string(),
                            doc_comment: None,
                        });
                    }
                }

                return Some(StructInfo {
                    name,
                    fields,
                    doc_comments,
                });
            }
        }
    }

    // Check if this is a single-line struct (e.g., "struct Foo { address token; uint256 amount; }")
    if let Some(open_brace) = struct_line.find('{') {
        if let Some(close_brace) = struct_line.find('}') {
            // Single line struct
            let content = &struct_line[open_brace + 1..close_brace];
            for field_str in content.split(';') {
                let field_str = field_str.trim();
                if field_str.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = field_str.split_whitespace().collect();
                if parts.len() >= 2 {
                    fields.push(FieldInfo {
                        ty: parts[0].to_string(),
                        name: parts[1].to_string(),
                        doc_comment: None,
                    });
                }
            }
        } else {
            // Multi-line struct, parse line by line
            let mut i = start_idx + 1;
            while i < lines.len() {
                let line = lines[i].trim();

                if line == "}" {
                    break;
                }

                if line.is_empty() || line.starts_with("//") {
                    i += 1;
                    continue;
                }

                // Parse field
                let parts: Vec<&str> =
                    line.trim_end_matches(';').split_whitespace().collect();
                if parts.len() >= 2 {
                    let ty = parts[0].to_string();
                    let name = parts[1].to_string();

                    // Check for doc comment on previous line
                    let doc_comment = if i > 0 {
                        let prev_line = lines[i - 1].trim();
                        if prev_line.starts_with("///") {
                            Some(prev_line.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    fields.push(FieldInfo {
                        name,
                        ty,
                        doc_comment,
                    });
                }

                i += 1;
            }
        }
    } else {
        // No brace on struct line, check if it's multi-line starting from next line
        let mut i = start_idx + 1;

        // Skip to the opening brace
        while i < lines.len() && !lines[i].trim().starts_with('{') {
            i += 1;
        }

        if i < lines.len() {
            i += 1; // Move past the opening brace

            while i < lines.len() {
                let line = lines[i].trim();

                if line == "}" {
                    break;
                }

                if line.is_empty() || line.starts_with("//") {
                    i += 1;
                    continue;
                }

                // Parse field
                let parts: Vec<&str> =
                    line.trim_end_matches(';').split_whitespace().collect();
                if parts.len() >= 2 {
                    let ty = parts[0].to_string();
                    let name = parts[1].to_string();

                    // Check for doc comment on previous line
                    let doc_comment = if i > 0 {
                        let prev_line = lines[i - 1].trim();
                        if prev_line.starts_with("///") {
                            Some(prev_line.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    fields.push(FieldInfo {
                        name,
                        ty,
                        doc_comment,
                    });
                }

                i += 1;
            }
        }
    }

    Some(StructInfo {
        name,
        fields,
        doc_comments,
    })
}

fn generate_unparsed_struct(struct_info: &StructInfo) -> String {
    let mut code = String::new();

    // Add doc comments
    code.push_str("/// For Swift & Kotlin usage only.\n");
    code.push_str("///\n");
    for doc in &struct_info.doc_comments {
        code.push_str(&format!("{}\n", doc));
    }

    // Add struct definition
    code.push_str("#[derive(uniffi::Record, Debug, Clone)]\n");
    code.push_str(&format!("pub struct Unparsed{} {{\n", struct_info.name));

    // Add fields
    for field in &struct_info.fields {
        if let Some(doc) = &field.doc_comment {
            code.push_str(&format!("    {}\n", doc));
        }

        // Check if this field type is another unparsed struct
        let field_type = if is_sol_struct_type(&field.ty) {
            format!("Unparsed{}", field.ty)
        } else {
            // Add Solidity type comment for primitive types
            code.push_str(&format!("    /// Solidity type: `{}`\n", field.ty));
            "String".to_string()
        };

        code.push_str(&format!("    pub {}: {},\n", field.name, field_type));
    }

    code.push_str("}");

    code
}

fn generate_try_from_impl(
    struct_info: &StructInfo,
    all_structs: &[StructInfo],
) -> String {
    let mut code = String::new();

    code.push_str(&format!(
        "impl TryFrom<Unparsed{}> for {} {{\n",
        struct_info.name, struct_info.name
    ));
    code.push_str("    type Error = crate::smart_account::SafeSmartAccountError;\n\n");
    code.push_str(&format!(
        "    fn try_from(value: Unparsed{}) -> Result<Self, Self::Error> {{\n",
        struct_info.name
    ));

    // Generate field conversions
    let mut field_conversions = Vec::new();

    for field in &struct_info.fields {
        let conversion = if is_sol_struct_type(&field.ty)
            && all_structs.iter().any(|s| s.name == field.ty)
        {
            // Nested struct conversion
            format!(
                "            {}: value.{}.try_into()?",
                field.name, field.name
            )
        } else {
            // Primitive type conversion using parse_from_ffi
            match field.ty.as_str() {
                "address" => format!(
                    "            {}: <alloy::primitives::Address as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.{}, \"{}\")?",
                    field.name, field.name, field.name
                ),
                "uint256" => format!(
                    "            {}: <alloy::primitives::U256 as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.{}, \"{}\")?",
                    field.name, field.name, field.name
                ),
                "uint128" => format!(
                    "            {}: <alloy::primitives::U128 as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.{}, \"{}\")?",
                    field.name, field.name, field.name
                ),
                "bytes" => format!(
                    "            {}: <alloy::primitives::Bytes as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.{}, \"{}\")?",
                    field.name, field.name, field.name
                ),
                _ => format!(
                    "            {}: value.{}.parse().map_err(|e| crate::smart_account::SafeSmartAccountError::InvalidInput {{ attribute: \"{}\", message: format!(\"failed to parse: {{}}\", e) }})?",
                    field.name, field.name, field.name
                ),
            }
        };

        field_conversions.push(conversion);
    }

    code.push_str("        Ok(Self {\n");
    code.push_str(&field_conversions.join(",\n"));
    code.push_str(",\n");
    code.push_str("        })\n");
    code.push_str("    }\n");
    code.push_str("}");

    code
}

fn is_sol_struct_type(ty: &str) -> bool {
    // Check if this is a known Solidity primitive type
    !matches!(
        ty,
        "address"
            | "uint256"
            | "uint128"
            | "uint64"
            | "uint32"
            | "uint16"
            | "uint8"
            | "int256"
            | "int128"
            | "int64"
            | "int32"
            | "int16"
            | "int8"
            | "bytes"
            | "bytes32"
            | "bytes16"
            | "bytes8"
            | "bytes4"
            | "bytes1"
            | "bool"
            | "string"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_detection_with_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn sync_method(&self) -> String {
                    "sync".to_string()
                }

                pub async fn async_method(&self) -> String {
                    "async".to_string()
                }
            }
        };

        assert!(has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_without_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn sync_method(&self) -> String {
                    "sync".to_string()
                }

                pub fn another_sync_method(&self) -> i32 {
                    42
                }
            }
        };

        assert!(!has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_ignores_private_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn public_sync(&self) -> String {
                    "sync".to_string()
                }

                async fn private_async(&self) -> String {
                    "private async".to_string()
                }
            }
        };

        // Private async functions should not trigger async detection
        assert!(!has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_with_mixed_visibility() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn public_sync(&self) -> String {
                    "sync".to_string()
                }

                pub async fn public_async(&self) -> String {
                    "public async".to_string()
                }

                async fn private_async(&self) -> String {
                    "private async".to_string()
                }
            }
        };

        // Should detect async because there's a public async function
        assert!(has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_tokio_args_generation() {
        // Test empty args with async
        let mut args = proc_macro2::TokenStream::new();
        if args.is_empty() {
            args = quote! { async_runtime = "tokio" };
        }
        assert_eq!(args.to_string(), "async_runtime = \"tokio\"");

        // Test existing args with async
        let mut args = quote! { callback_interface = "SomeInterface" };
        args = quote! { #args, async_runtime = "tokio" };
        assert_eq!(
            args.to_string(),
            "callback_interface = \"SomeInterface\" , async_runtime = \"tokio\""
        );
    }
}
