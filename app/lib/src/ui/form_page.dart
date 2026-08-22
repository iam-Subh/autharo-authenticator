import 'package:flutter/material.dart';

/// A form page whose action button is pinned below the scrolling fields.
///
/// # The two defects this exists to prevent
///
/// Both were found on a phone and were invisible on the host, and both come
/// from putting the action button inside the scroll view.
///
/// **A `Form` stops validating fields that scroll away.** `Form.validate()`
/// only reaches fields that are currently built, and a `ListView` disposes its
/// off-screen children. Scrolling down to reach the button unregisters the
/// fields above it, and `validate()` then returns `true` having run no
/// validator at all — a passing check that checked nothing.
///
/// **The soft keyboard covers the button.** With a field focused, the keyboard
/// takes the bottom of the screen. A button at the end of a long scroll view
/// ends up behind it, and a tap aimed at the button lands on the keyboard.
///
/// Pinning the action fixes both. It is never disposed, so it is always
/// tappable; and because `Scaffold` resizes its body for the keyboard by
/// default, the footer is pushed above the keyboard rather than behind it.
///
/// The fields may still scroll away, so **a page using this must still
/// validate from its controllers rather than through `Form.validate()`** —
/// the controllers are owned by the `State` and outlive the widgets. See
/// [errorMessage], which is rendered next to the action for the same reason:
/// the field that would show an inline error may not be on screen.
class FormPage extends StatelessWidget {
  const FormPage({
    super.key,
    required this.title,
    required this.children,
    required this.actionLabel,
    required this.onAction,
    this.busy = false,
    this.errorMessage,
    this.secondaryAction,
    this.formKey,
  });

  final String title;

  /// The scrolling content: the explanation, the fields, anything else.
  final List<Widget> children;

  final String actionLabel;

  /// Null disables the button. [busy] shows a spinner in its place.
  final VoidCallback? onAction;
  final bool busy;

  /// Shown directly above the action, where the user is already looking.
  final String? errorMessage;

  /// An optional second, lower-emphasis action beneath the first.
  final Widget? secondaryAction;

  /// Passed through when the page still wants inline field errors for fields
  /// that happen to be visible. It must not be the only check.
  final GlobalKey<FormState>? formKey;

  @override
  Widget build(BuildContext context) {
    final content = Column(
      children: [
        Expanded(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 8),
            children: children,
          ),
        ),
        // Outside the scroll view: never disposed, never behind the keyboard.
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (errorMessage != null) ...[
                  Text(
                    errorMessage!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                  const SizedBox(height: 12),
                ],
                FilledButton(
                  onPressed: busy ? null : onAction,
                  child: busy
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Text(actionLabel),
                ),
                if (secondaryAction != null) ...[
                  const SizedBox(height: 8),
                  secondaryAction!,
                ],
              ],
            ),
          ),
        ),
      ],
    );

    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: formKey == null ? content : Form(key: formKey, child: content),
    );
  }
}
