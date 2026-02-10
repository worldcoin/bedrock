#![deny(clippy::all, clippy::nursery)]
// TODO: pedantic after we decide whether `bedrock_sol` is stable and will remain

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, ImplItem, ImplItemFn, ItemImpl, Stmt,
    Variant, Visibility,
};

/// Procedural macro that enhances error enums with generic error handling
///
/// This macro automatically:
/// 1. Adds `#[derive(Debug, thiserror::Error, uniffi::Error)]`
/// 2. Adds a `Generic { message: String }` variant if not already present
/// 3. Adds a `FileSystem(FileSystemError)` variant if not already present
/// 4. Implements `From<anyhow::Error>` for the error type
/// 5. Implements `From<FileSystemError>` for the error type (via thiserror's #[from])
/// 6. Provides helper methods for error conversion
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
/// - `#[derive(Debug, thiserror::Error, uniffi::Error)]`
/// - `Generic { message: String }` variant
/// - `FileSystem(FileSystemError)` variant
/// - `impl From<anyhow::Error> for MyError`
/// - `impl From<FileSystemError> for MyError`
///
/// Now you can use filesystem operations with automatic error conversion:
/// ```rust,ignore
/// fn my_function() -> Result<String, MyError> {
///     // FileSystemError automatically converts to MyError::FileSystem
///     let data = _bedrock_fs.read_file("config.json")?;
///     Ok(String::from_utf8_lossy(&data).to_string())
/// }
/// ```
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

            // Check if FileSystem variant already exists
            let has_filesystem = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "FileSystem");

            // Collect existing variants
            let mut variants = data_enum.variants.clone();

            // Add Generic variant if it doesn't exist
            if !has_generic {
                let generic_variant: Variant = syn::parse_quote! {
                    /// A generic error that can wrap any anyhow error.
                    #[error("Generic error: {error_message}")]
                    Generic {
                        /// The error message from the wrapped error.
                        error_message: String
                    }
                };
                variants.push(generic_variant);
            }

            // Add FileSystem variant if it doesn't exist
            if !has_filesystem {
                let filesystem_variant: Variant = syn::parse_quote! {
                    /// Filesystem operation error.
                    #[error(transparent)]
                    FileSystem(#[from] crate::primitives::filesystem::FileSystemError)
                };
                variants.push(filesystem_variant);
            }

            // Generate the enhanced enum with automatic derives and attributes
            quote! {
                // Automatically import anyhow::Context for convenience
                use anyhow::Context;

                #[derive(Debug, thiserror::Error, uniffi::Error)]
                #(#attrs)*
                #visibility enum #enum_name #generics {
                    #variants
                }

                impl #generics From<anyhow::Error> for #enum_name #generics {
                    fn from(err: anyhow::Error) -> Self {
                        Self::Generic {
                            error_message: {
                                // Include the full error chain in the error_message
                                let mut error_message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    error_message.push_str(" (caused by: ");
                                    error_message.push_str(&chain.join(" -> "));
                                    error_message.push(')');
                                }

                                error_message
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
                            error_message: {
                                // Format the error message directly without double prefixing
                                let mut error_message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    error_message.push_str(" (caused by: ");
                                    error_message.push_str(&chain.join(" -> "));
                                    error_message.push(')');
                                }

                                format!("{}: {}", prefix, error_message)
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

/// Procedural macro that wraps `uniffi::export` and automatically injects logging context and filesystem middleware
///
/// This macro automatically:
/// 1. Forwards the attribute to `#[uniffi::export]`
/// 2. Injects `let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new("StructName");` at the start of every `pub fn`
/// 3. Injects a private `_bedrock_fs` field of type FileSystemMiddleware to the struct
/// 4. Extracts the struct/trait name from the impl block for context
/// 5. Automatically adds `async_runtime = "tokio"` if any async functions are detected
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_export]
/// impl MyStruct {
///     pub fn some_method(&self) -> String {
///         // _bedrock_logger_ctx and _bedrock_fs are automatically injected here
///         debug!("This will be prefixed with [Bedrock][MyStruct]");
///         
///         // Use the filesystem with automatic path prefixing
///         let data = _bedrock_fs.read_file("config.json").unwrap();
///         
///         "result".to_string()
///     }
///     
///     pub async fn async_method(&self) -> String {
///         // async_runtime = "tokio" is automatically added to uniffi::export
///         // _bedrock_fs is available here too
///         _bedrock_fs.write_file("output.txt", b"data".to_vec()).unwrap();
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
        syn::Type::Path(type_path) => type_path.path.segments.last().map_or_else(
            || "Unknown".to_string(),
            |segment| segment.ident.to_string(),
        ),
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
                    inject_logging_and_filesystem_context(&mut new_method, &type_name);
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

/// Convert a PascalCase string to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_was_uppercase = false;
    let chars: Vec<char> = s.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_uppercase() {
            // Don't add underscore at the beginning
            if !result.is_empty() {
                // Add underscore if:
                // 1. Previous char was lowercase (e.g., "aB" -> "a_b")
                // 2. Current char is uppercase followed by lowercase (e.g., "ABc" -> "a_bc")
                let prev_was_lowercase = i > 0 && chars[i - 1].is_lowercase();
                let next_is_lowercase =
                    i + 1 < chars.len() && chars[i + 1].is_lowercase();

                if prev_was_lowercase || (prev_was_uppercase && next_is_lowercase) {
                    result.push('_');
                }
            }
            result.push(ch.to_lowercase().next().unwrap());
            prev_was_uppercase = true;
        } else {
            result.push(ch);
            prev_was_uppercase = false;
        }
    }

    result
}

/// Inject logging context and filesystem middleware at the start of a function body
fn inject_logging_and_filesystem_context(method: &mut ImplItemFn, type_name: &str) {
    // Convert type name to snake_case for filesystem prefix
    let snake_case_name = to_snake_case(type_name);

    // Create the filesystem middleware statement with snake_case name
    let fs_stmt: Stmt = syn::parse_quote! {
        let _bedrock_fs = crate::primitives::filesystem::create_middleware(#snake_case_name);
    };

    // Create the logging context statement (keep original PascalCase for logging)
    let context_stmt: Stmt = syn::parse_quote! {
        let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new(#type_name);
    };

    // Insert both at the beginning of the function body
    method.block.stmts.insert(0, fs_stmt);
    method.block.stmts.insert(1, context_stmt);
}

/// Procedural macro that wraps `alloy::sol!` and generates unparsed versions of structs
///
/// This macro:
/// 1. Forwards everything to `alloy::sol!`
/// 2. For structs marked with `#[unparsed]`, generates:
///    - An `Unparsed{StructName}` struct with all String fields
///    - A `TryFrom<Unparsed{StructName}>` implementation
///
/// # Usage
///
/// ```rust,ignore
/// bedrock_sol! {
///     #[derive(serde::Serialize)]
///     #[unparsed]
///     struct TokenPermissions {
///         address token;
///         uint256 amount;
///     }
///     
///     #[unparsed]
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
    // 1: Initialize input processing
    let input_str = input.to_string();
    let lines = input_str.lines().collect::<Vec<_>>();

    // 2: Find structs with #[unparsed] attributes and clean the input
    let mut unparsed_struct_names = Vec::new();
    let mut cleaned_lines = Vec::new();
    let mut next_struct_is_unparsed = false;

    // 2.1: Process each input line to identify and clean unparsed attributes
    for line in lines {
        let trimmed_line = line.trim();

        // 2.2: Handle lines containing #[unparsed] attribute
        if trimmed_line.contains("#[unparsed]") {
            next_struct_is_unparsed = true;

            // 2.3: Remove #[unparsed] attribute to clean the input for alloy::sol!
            let cleaned_line =
                trimmed_line.replace("#[unparsed]", "").trim().to_string();
            if !cleaned_line.is_empty() {
                cleaned_lines.push(cleaned_line.clone());

                // 2.4: Check if struct definition is on same line as #[unparsed]
                if cleaned_line.contains(" struct ") {
                    // 2.5: Extract struct name for unparsed generation tracking
                    if let Some(struct_pos) = cleaned_line.find(" struct ") {
                        let remaining = &cleaned_line[struct_pos + " struct ".len()..];
                        if let Some(struct_name) = remaining
                            .split_whitespace()
                            .next()
                            .map(|s| s.trim_end_matches('{'))
                        {
                            unparsed_struct_names.push(struct_name.to_string());
                        }
                    }
                    next_struct_is_unparsed = false;
                }
            }
            continue;
        }

        // 2.6: Handle struct definitions on subsequent lines after #[unparsed]
        if next_struct_is_unparsed && trimmed_line.contains(" struct ") {
            // 2.7: Extract struct name for deferred unparsed generation tracking
            if let Some(struct_pos) = trimmed_line.find(" struct ") {
                let remaining = &trimmed_line[struct_pos + " struct ".len()..];
                if let Some(struct_name) = remaining
                    .split_whitespace()
                    .next()
                    .map(|s| s.trim_end_matches('{'))
                {
                    unparsed_struct_names.push(struct_name.to_string());
                }
            }
            next_struct_is_unparsed = false;
        }

        // 2.8: Include all lines in cleaned output for alloy::sol!
        cleaned_lines.push(line.to_string());
    }

    // 3: Parse all structs in the cleaned input
    let mut all_structs = Vec::new();
    let mut i = 0;

    // 3.1: Convert to slice format for parsing function
    let cleaned_lines_refs: Vec<&str> =
        cleaned_lines.iter().map(|s| s.as_str()).collect();

    // 3.2: Scan lines to find and parse struct definitions
    while i < cleaned_lines_refs.len() {
        let line = cleaned_lines_refs[i].trim();

        // 3.3: Parse struct when found and collect metadata
        if line.contains(" struct ") {
            if let Some(struct_info) = parse_struct_definition(&cleaned_lines_refs, i) {
                all_structs.push(struct_info);
            }
        }
        i += 1;
    }

    // 4: Filter to only the structs that should have unparsed versions
    let unparsed_structs: Vec<_> = all_structs
        .iter()
        .filter(|s| unparsed_struct_names.contains(&s.name))
        .collect();

    // 4.1: Generate the unparsed structs and TryFrom implementations
    let mut generated_code = String::new();

    // 4.2: Create unparsed struct and conversion code for each marked struct
    for struct_info in &unparsed_structs {
        generated_code.push_str(&generate_unparsed_struct(struct_info));
        generated_code.push_str("\n\n");
        generated_code.push_str(&generate_try_from_impl(struct_info, &all_structs));
        generated_code.push_str("\n\n");
    }

    // 5: Combine the cleaned sol! invocation with the generated code
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

    // 5.1: Parse and return the final token stream
    output.parse().unwrap_or_else(|e| {
        panic!("Failed to parse macro output: {e}\nGenerated output:\n{output}");
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

#[allow(clippy::cognitive_complexity)]
fn parse_struct_definition(lines: &[&str], start_idx: usize) -> Option<StructInfo> {
    // 9: Parse struct definition from multiple line formats (single/multi-line)
    let struct_line = lines[start_idx].trim();

    // 9.1: Extract struct name from declaration line
    let struct_pos = struct_line.find(" struct ")? + " struct ".len();
    let remaining = &struct_line[struct_pos..];
    let name = remaining
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
                // Only decrement if idx > 0
                idx = idx.saturating_sub(1);
            } else if line.is_empty() {
                if idx == 0 {
                    break;
                }
                // Only decrement if idx > 0
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

    // 6: Generate unparsed struct with String fields for foreign bindings
    code.push_str("/// For Swift & Kotlin usage only.\n");
    code.push_str("///\n");
    for doc in &struct_info.doc_comments {
        code.push_str(&format!("{doc}\n"));
    }

    // 6.1: Add struct definition with uniffi Record derive
    code.push_str("#[derive(uniffi::Record, Debug, Clone)]\n");
    code.push_str(&format!("pub struct Unparsed{} {{\n", struct_info.name));

    // 6.2: Convert each field to String type for safe foreign binding
    for field in &struct_info.fields {
        if let Some(doc) = &field.doc_comment {
            code.push_str(&format!("    {doc}\n"));
        }

        // 6.3: Use nested unparsed struct for complex types, String for primitives
        let field_type = if is_sol_struct_type(&field.ty) {
            // 6.4: Add Solidity type comment for nested struct types
            code.push_str(&format!("    /// Nested struct type: `{}`\n", field.ty));
            format!("Unparsed{}", field.ty)
        } else {
            // 6.4: Add Solidity type comment for primitive types
            code.push_str(&format!("    /// Solidity type: `{}`\n", field.ty));
            "String".to_string()
        };

        code.push_str(&format!("    pub {}: {},\n", field.name, field_type));
    }

    code.push('}');

    code
}

fn generate_try_from_impl(
    struct_info: &StructInfo,
    all_structs: &[StructInfo],
) -> String {
    let mut code = String::new();

    // 7: Generate TryFrom implementation for converting from unparsed to typed structs
    code.push_str(&format!(
        "impl TryFrom<Unparsed{}> for {} {{\n",
        struct_info.name, struct_info.name
    ));
    code.push_str("    type Error = crate::primitives::PrimitiveError;\n\n");
    code.push_str(&format!(
        "    fn try_from(value: Unparsed{}) -> Result<Self, Self::Error> {{\n",
        struct_info.name
    ));

    // 7.1: Generate field conversions with appropriate parsing logic
    let mut field_conversions = Vec::new();

    // 7.2: Process each field with type-specific conversion
    for field in &struct_info.fields {
        let conversion = if is_sol_struct_type(&field.ty)
            && all_structs.iter().any(|s| s.name == field.ty)
        {
            // 7.3: Handle nested struct conversion via recursive TryFrom
            format!(
                "            {}: value.{}.try_into()?",
                field.name, field.name
            )
        } else {
            // 7.4: Handle primitive type conversion using specialized parsers
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
                    "            {}: value.{}.parse().map_err(|e| crate::primitives::PrimitiveError::InvalidInput {{ attribute: \"{}\".to_string(), error_message: format!(\"failed to parse: {{}}\", e) }})?",
                    field.name, field.name, field.name
                ),
            }
        };

        field_conversions.push(conversion);
    }

    // 7.5: Combine all field conversions into struct constructor
    code.push_str("        Ok(Self {\n");
    code.push_str(&field_conversions.join(",\n"));
    code.push_str(",\n");
    code.push_str("        })\n");
    code.push_str("    }\n");
    code.push('}');

    code
}

fn is_sol_struct_type(ty: &str) -> bool {
    // 8: Determine if type is a custom struct (not a Solidity primitive)
    !matches!(
        ty,
        "address"
            | "uint256"
            | "uint160"
            | "uint128"
            | "uint64"
            | "uint48"
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

    #[test]
    fn test_bedrock_error_includes_filesystem() {
        // Test that bedrock_error macro includes FileSystem variant
        let input: DeriveInput = syn::parse_quote! {
            pub enum TestError {
                #[error("custom error")]
                Custom,
            }
        };

        // Simulate what the macro does
        if let Data::Enum(data_enum) = &input.data {
            let has_filesystem = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "FileSystem");

            // Initially should not have FileSystem variant
            assert!(!has_filesystem);

            // After macro processing, it should add FileSystem variant
            let mut variants = data_enum.variants.clone();

            // Add FileSystem variant (simulating macro behavior)
            let filesystem_variant: Variant = syn::parse_quote! {
                /// Filesystem operation error.
                #[error(transparent)]
                FileSystem(#[from] crate::primitives::filesystem::FileSystemError)
            };
            variants.push(filesystem_variant);

            // Now check it has FileSystem variant
            let has_filesystem_after =
                variants.iter().any(|variant| variant.ident == "FileSystem");
            assert!(has_filesystem_after);
        } else {
            panic!("Expected enum");
        }
    }

    #[test]
    fn test_to_snake_case() {
        // Basic cases
        assert_eq!(to_snake_case("MyStruct"), "my_struct");
        assert_eq!(to_snake_case("TestModule"), "test_module");
        assert_eq!(to_snake_case("SimpleTest"), "simple_test");

        // Single word cases
        assert_eq!(to_snake_case("Simple"), "simple");
        assert_eq!(to_snake_case("SIMPLE"), "simple");

        // Acronyms and complex cases
        assert_eq!(to_snake_case("HTTPClient"), "http_client");
        assert_eq!(to_snake_case("XMLParser"), "xml_parser");
        assert_eq!(to_snake_case("IOError"), "io_error");
        assert_eq!(to_snake_case("URLPath"), "url_path");

        // Multiple uppercase in a row
        assert_eq!(to_snake_case("XMLHTTPRequest"), "xmlhttp_request");
        assert_eq!(to_snake_case("HTTPSConnection"), "https_connection");

        // Already snake_case
        assert_eq!(to_snake_case("already_snake_case"), "already_snake_case");

        // Mixed cases
        assert_eq!(
            to_snake_case("getHTTPResponseCode"),
            "get_http_response_code"
        );
        assert_eq!(to_snake_case("ParseHTMLString"), "parse_html_string");

        // Edge cases
        assert_eq!(to_snake_case(""), "");
        assert_eq!(to_snake_case("A"), "a");
        assert_eq!(to_snake_case("AB"), "ab");
        assert_eq!(to_snake_case("ABC"), "abc");
        assert_eq!(to_snake_case("ABc"), "a_bc");
    }
}
