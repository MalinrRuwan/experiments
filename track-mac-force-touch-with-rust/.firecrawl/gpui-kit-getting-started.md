[![](https://gpui-kit.com/logo.svg)GPUI Kit](https://gpui-kit.com/)

[Docs](https://gpui-kit.com/docs) [Component](https://gpui-kit.com/component) [Base](https://gpui-kit.com/base) [Shell](https://gpui-kit.com/shell) [App Stories](https://gpui-kit.com/apps)

Resources

[API Doc](https://docs.rs/gpui-kit) [Contributors](https://gpui-kit.com/contributors) [Releases](https://gpui-kit.com/releases) [Issues](https://github.com/longbridge/gpui-kit/issues) [Discussion](https://github.com/longbridge/gpui-kit/discussions)

Search `/`

## Search documentation

Search documentation

Find components, guides, API references and examples.

`↑`  `↓` Navigate`↵` Open`Esc` Close

[14.2k](https://github.com/longbridge/gpui-kit "14233 stars on GitHub") [中](https://gpui-kit.com/zh-CN/docs/getting-started)

GPUI Kit

- [GPUI Kit](https://gpui-kit.com/docs)
- [Installation](https://gpui-kit.com/docs/installation)
- [Getting Started](https://gpui-kit.com/docs/getting-started)
- [Design Guides](https://gpui-kit.com/docs/design-guides)
- [Coding Guides](https://gpui-kit.com/docs/coding-guides)
- [Testing](https://gpui-kit.com/docs/test)
- [I18n](https://gpui-kit.com/docs/i18n)
- [Icons & Assets](https://gpui-kit.com/docs/assets)
- [Context](https://gpui-kit.com/docs/context)
- [ElementId](https://gpui-kit.com/docs/element_id)
- [FPS Monitor](https://gpui-kit.com/docs/fps)
- [Comparison](https://gpui-kit.com/docs/comparison)
- [Fonts](https://gpui-kit.com/docs/fonts)

# Getting Started

## [\#](https://gpui-kit.com/docs/getting-started/\#installation) Installation

Add dependencies to your `Cargo.toml`:

```
[dependencies]
gpui-kit = "0.6"
anyhow = "1.0"
```

`gpui-kit` always pulls in GPUI and `gpui-base`, and by default `gpui-component` and the default icon set. To manage your own assets, keep only the features you need:

```
gpui-kit = { version = "0.6", default-features = false, features = ["component"] }
```

See [Icons & Assets](https://gpui-kit.com/docs/assets) for more details.

## [\#](https://gpui-kit.com/docs/getting-started/\#quick-start) Quick Start

Here’s a simple example to get you started:

```
use gpui_kit::component::button::*;
use gpui_kit::component::*;
use gpui_kit::*;

pub struct HelloWorld;

impl Render for HelloWorld {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .v_flex()
            .gap_2()
            .size_full()
            .items_center()
            .justify_center()
            .child("Hello, World!")
            .child(
                Button::new("ok")
                    .primary()
                    .label("Let's Go!")
                    .on_click(|_, _, _| println!("Clicked!")),
            )
    }
}

fn main() {
    let app = gpui_kit::application().with_assets(gpui_kit::assets::Assets);

    app.run(move |cx| {
        // This must be called before using any GPUI Component features.
        gpui_kit::init(cx);

        cx.spawn(async move |cx| {
            cx.open_window(WindowOptions::default(), |window, cx| {
                let view = cx.new(|_| HelloWorld);
                // This first level on the window, should be a Root.
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("Failed to open window");
        })
        .detach();
    });
}
```

Make sure to call `gpui_kit::init(cx);` at first line inside the `app.run` closure. This initializes the GPUI Component system.

This is required for theming and other global settings to work correctly.

## [\#](https://gpui-kit.com/docs/getting-started/\#basic-concepts) Basic Concepts

### [\#](https://gpui-kit.com/docs/getting-started/\#stateless-elements) Stateless Elements

GPUI Component uses stateless [RenderOnce](https://docs.rs/gpui/latest/gpui/trait.RenderOnce.html) elements, making them simple and predictable. State management is handled at the view level, not in individual components.

They are all implemented [IntoElement](https://docs.rs/gpui/latest/gpui/trait.IntoElement.html) types.

For example:

```
struct MyView;

impl Render for MyView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .child(Button::new("btn").label("Click Me"))
            .child(Tag::secondary().child("Secondary"))
    }
}
```

### [\#](https://gpui-kit.com/docs/getting-started/\#stateful-components) Stateful Components

See the [tested application recipes](https://github.com/longbridge/gpui-kit/tree/main/examples/ai_recipes) for a complete window with retained subscriptions, icons, and overlay layers. `Root` must wrap each window, and the application content must render the dialog, sheet, and notification layers it uses.

Controls such as Input, List, and DataTable use retained state entities. Store that state on the owning view and construct the styled element from it during render.

Create the \[Entity\] once, outside render:

```
use gpui_kit::component::{
    ActiveTheme, IconName, Root, WindowExt,
    button::Button,
    checkbox::Checkbox,
    form::{Field, Form},
    input::{Input, InputEvent, InputState},
    radio::RadioGroup,
    switch::Switch,
};
use gpui_kit::{
    AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Subscription, Window, div,
};

pub struct Settings {
    pub name: Entity<InputState>,
    pub preview: SharedString,
    pub changes: usize,
    enabled: bool,
    remember: bool,
    delivery: Option<usize>,
    _subscriptions: Vec<Subscription>,
}

impl Settings {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let name = cx.new(|cx| InputState::new(window, cx).placeholder("Name"));
        let subscription = cx.subscribe_in(&name, window, |this, state, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                this.preview = state.read(cx).value().to_string().into();
                this.changes += 1;
                cx.notify();
            }
        });
        Self {
            name,
            preview: "".into(),
            changes: 0,
            enabled: false,
            remember: false,
            delivery: Some(0),
            _subscriptions: vec![subscription],
        }
    }
}

impl Render for Settings {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .p_4()
            .gap_3()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child("Profile")
            .child(
                Form::new()
                    .child(Field::new().label("Name").child(Input::new(&self.name)))
                    .child(Field::new().label("Preview").child(self.preview.clone()))
                    .child(
                        Field::new().label_indent(false).child(
                            Checkbox::new("remember")
                                .label("Remember name")
                                .checked(self.remember)
                                .on_change(cx.listener(|this, value, _, cx| {
                                    this.remember = *value;
                                    cx.notify();
                                })),
                        ),
                    )
                    .child(
                        Field::new().label_indent(false).child(
                            Switch::new("enabled")
                                .label("Enable notifications")
                                .checked(self.enabled)
                                .on_change(cx.listener(|this, value, _, cx| {
                                    this.enabled = *value;
                                    cx.notify();
                                })),
                        ),
                    )
                    .child(
                        Field::new().label("Delivery").child(
                            RadioGroup::new("delivery")
                                .children(["Immediately", "Daily summary"])
                                .selected_index(self.delivery)
                                .on_change(cx.listener(|this, value, _, cx| {
                                    this.delivery = Some(*value);
                                    cx.notify();
                                })),
                        ),
                    )
                    .footer(
                        Button::new("about")
                            .label("About…")
                            .icon(IconName::Info)
                            .on_click(|_, window, cx| {
                                window.open_dialog(cx, |dialog, _, _| {
                                    dialog.title("About").child("A complete GPUI Kit window")
                                });
                            }),
                    ),
            )
            .children(Root::render_dialog_layer(window, cx))
            .children(Root::render_sheet_layer(window, cx))
            .children(Root::render_notification_layer(window, cx))
    }
}
```

### [\#](https://gpui-kit.com/docs/getting-started/\#theming) Theming

All components support theming through the built-in `Theme` system:

```
use gpui_kit::component::{ActiveTheme, Theme};

// Access theme colors in your components
cx.theme().primary
cx.theme().background
cx.theme().foreground
```

### [\#](https://gpui-kit.com/docs/getting-started/\#sizing) Sizing

Most components support multiple sizes:

```
Button::new("btn").small()
Button::new("btn").medium() // default
Button::new("btn").large()
Button::new("btn").xsmall()
```

### [\#](https://gpui-kit.com/docs/getting-started/\#variants) Variants

Components offer different visual variants:

```
Button::new("btn").primary()
Button::new("btn").danger()
Button::new("btn").warning()
Button::new("btn").success()
Button::new("btn").ghost()
Button::new("btn").outline()
```

## [\#](https://gpui-kit.com/docs/getting-started/\#icons) Icons

Icons are not bundled with GPUI Component to keep the library lightweight.

Continue read [Icons & Assets](https://gpui-kit.com/docs/assets) to learn how to add icons to your project.

GPUI Component has an `Icon` element, but does not include SVG files by default.

The examples use [Lucide](https://lucide.dev/) icons. You can use any icons you like by naming the SVG files as defined in `IconName`. Add the icons you need to your project.

```
use gpui_kit::component::{Icon, IconName};

Icon::new(IconName::Check)
Icon::new(IconName::Search).small()
```

## [\#](https://gpui-kit.com/docs/getting-started/\#next-steps) Next Steps

Explore the component documentation to learn more about each component:

- [Button](https://gpui-kit.com/component/button) \- Interactive button component
- [Input](https://gpui-kit.com/component/input) \- Text input with validation
- [Dialog](https://gpui-kit.com/component/dialog) \- Dialog and modal windows
- [DataTable](https://gpui-kit.com/component/data-table) \- High-performance data tables
- [More components…](https://gpui-kit.com/component)

## [\#](https://gpui-kit.com/docs/getting-started/\#development) Development

To run the component gallery:

```
cargo run
```

More examples can be found in the `examples` directory:

```
cargo run --example <example_name>
```

On this page

- [Installation](https://gpui-kit.com/docs/getting-started/#installation)
- [Quick Start](https://gpui-kit.com/docs/getting-started/#quick-start)
- [Basic Concepts](https://gpui-kit.com/docs/getting-started/#basic-concepts)
- [Stateless Elements](https://gpui-kit.com/docs/getting-started/#stateless-elements)
- [Stateful Components](https://gpui-kit.com/docs/getting-started/#stateful-components)
- [Theming](https://gpui-kit.com/docs/getting-started/#theming)
- [Sizing](https://gpui-kit.com/docs/getting-started/#sizing)
- [Variants](https://gpui-kit.com/docs/getting-started/#variants)
- [Icons](https://gpui-kit.com/docs/getting-started/#icons)
- [Next Steps](https://gpui-kit.com/docs/getting-started/#next-steps)
- [Development](https://gpui-kit.com/docs/getting-started/#development)

**GPUI Kit**

Open source under the Apache-2.0 License, developed by [Longbridge](https://longbridge.com/).

Built on [GPUI](https://gpui.rs/), the UI framework from [Zed Industries](https://zed.dev/), also Apache-2.0.

[Design Guides](https://gpui-kit.com/docs/design-guides) [Coding Guides](https://gpui-kit.com/docs/coding-guides) [App Stories](https://gpui-kit.com/apps) [Contributors](https://gpui-kit.com/contributors) [Releases](https://gpui-kit.com/releases) [Skills](https://gpui-kit.com/skills) [llms-full.txt](https://gpui-kit.com/llms-full.txt) [Report Bug](https://github.com/longbridge/gpui-kit/issues) [Discussion](https://github.com/longbridge/gpui-kit/discussions)

Icons by [Lucide](https://lucide.dev/) and [Isocons](https://isocons.app/).