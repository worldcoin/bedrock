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
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_export]
/// impl MyStruct {
///     pub fn some_method(&self) -> String {
///         // _bedrock_logger_ctx is automatically injected here
///         debug!("This will be prefixed with [MyStruct]");
///         "result".to_string()
///     }
/// }
/// ```
///
/// This will automatically add logging context to all public methods in the impl block.
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
    let args = proc_macro2::TokenStream::from(args);
    quote! {
        #[uniffi::export(#args)]
        #new_impl
    }
    .into()
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
