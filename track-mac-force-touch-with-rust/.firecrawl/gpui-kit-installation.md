[![](https://gpui-kit.com/logo.svg)GPUI Kit](https://gpui-kit.com/)

[Docs](https://gpui-kit.com/docs) [Component](https://gpui-kit.com/component) [Base](https://gpui-kit.com/base) [Shell](https://gpui-kit.com/shell) [App Stories](https://gpui-kit.com/apps)

Resources

[API Doc](https://docs.rs/gpui-kit) [Contributors](https://gpui-kit.com/contributors) [Releases](https://gpui-kit.com/releases) [Issues](https://github.com/longbridge/gpui-kit/issues) [Discussion](https://github.com/longbridge/gpui-kit/discussions)

Search `/`

## Search documentation

Search documentation

Find components, guides, API references and examples.

`↑`  `↓` Navigate`↵` Open`Esc` Close

[14.2k](https://github.com/longbridge/gpui-kit "14233 stars on GitHub") [中](https://gpui-kit.com/zh-CN/docs/installation)

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

# Installation

Before you start to build your application with `gpui-component`, you need to install the library.

## [\#](https://gpui-kit.com/docs/installation/\#system-requirements) System Requirements

We can development application on macOS, Windows or Linux.

### [\#](https://gpui-kit.com/docs/installation/\#macos) macOS

- macOS 15 or later
- Xcode command line tools

## [\#](https://gpui-kit.com/docs/installation/\#windows) Windows

- Windows 10 or later

There have a bootstrap script to help install the required toolchain and dependencies.

You can run the script in PowerShell:

```
.\script\install-window.ps1
```

## [\#](https://gpui-kit.com/docs/installation/\#linux) Linux

Run `./script/bootstrap` to install system dependencies.

## [\#](https://gpui-kit.com/docs/installation/\#rust-and-cargo) Rust and Cargo

We use Rust programming language to build the `gpui-component` library. Make sure you have Rust and Cargo installed on your system.

- Rust 1.90 or later
- Cargo (comes with Rust)

To install the `gpui-component` library, you can use Cargo, the Rust package manager. Add the following line to your `Cargo.toml` file under the `[dependencies]` section:

```
gpui-kit = "0.6"
```

`gpui-kit` depends on the matching GPUI crates for you, so your application never lists GPUI itself. `use gpui_kit::*;` is GPUI, and the layers are reachable by name: `gpui_kit::component` (the styled components), `gpui_kit::base`, `gpui_kit::assets` and `gpui_kit::platform`.

## [\#](https://gpui-kit.com/docs/installation/\#faster-development-builds) Faster development builds

Debug builds compile GPUI, the component library and the text stack without
optimizations, which makes a `cargo run` build of your application render
noticeably slower than a release build. Optimize just those crates while your
own code stays a fast, debuggable debug build. Profiles only take effect in
the root `Cargo.toml` of your application (or workspace):

```
[profile.dev.package]
gpui-pre = { opt-level = 3 }
gpui-component = { opt-level = 3 }
gpui-kit = { opt-level = 3 }
gpui-kit-assets = { opt-level = 3 }
gpui-pre-macros = { opt-level = 3 }
gpui-pre-platform = { opt-level = 3 }
rustybuzz = { opt-level = 3 }
taffy = { opt-level = 3 }
ttf-parser = { opt-level = 3 }
```

On this page

- [System Requirements](https://gpui-kit.com/docs/installation/#system-requirements)
- [macOS](https://gpui-kit.com/docs/installation/#macos)
- [Windows](https://gpui-kit.com/docs/installation/#windows)
- [Linux](https://gpui-kit.com/docs/installation/#linux)
- [Rust and Cargo](https://gpui-kit.com/docs/installation/#rust-and-cargo)
- [Faster development builds](https://gpui-kit.com/docs/installation/#faster-development-builds)

**GPUI Kit**

Open source under the Apache-2.0 License, developed by [Longbridge](https://longbridge.com/).

Built on [GPUI](https://gpui.rs/), the UI framework from [Zed Industries](https://zed.dev/), also Apache-2.0.

[Design Guides](https://gpui-kit.com/docs/design-guides) [Coding Guides](https://gpui-kit.com/docs/coding-guides) [App Stories](https://gpui-kit.com/apps) [Contributors](https://gpui-kit.com/contributors) [Releases](https://gpui-kit.com/releases) [Skills](https://gpui-kit.com/skills) [llms-full.txt](https://gpui-kit.com/llms-full.txt) [Report Bug](https://github.com/longbridge/gpui-kit/issues) [Discussion](https://github.com/longbridge/gpui-kit/discussions)

Icons by [Lucide](https://lucide.dev/) and [Isocons](https://isocons.app/).