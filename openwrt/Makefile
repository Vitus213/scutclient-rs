#
# Copyright (C) 2025 Scutclient Project
#
# This is free software, licensed under the AGPL-3.0 license.

include $(TOPDIR)/rules.mk

PKG_NAME:=scutclient-rs
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/yourusername/scutclient-rs.git
PKG_SOURCE_VERSION:=main
PKG_MIRROR_HASH:=skip

include $(INCLUDE_DIR)/package.mk

define Package/scutclient-rs
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SCUT Dr.com(X) client in Rust
  URL:=https://github.com/yourusername/scutclient-rs
  DEPENDS:=+libc +libgcc
  MAINTAINER:=Scutclient Project
endef

define Package/scutclient-rs/description
  SCUT Dr.com(X) authentication client written in Rust.
  Supports Dr.com version 5.20 and 6.x protocols with UDP authentication.
  Features UCI configuration, procd integration, and hook scripts.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./Cargo.toml $(PKG_BUILD_DIR)/
	$(CP) ./Cargo.lock $(PKG_BUILD_DIR)/
endef

define Build/Compile
	( cd $(PKG_BUILD_DIR); \
		CARGO_HOME=$(PKG_BUILD_DIR)/.cargo \
		RUSTFLAGS="-C target-feature=-crt-static" \
		cargo build --release --target=$(GNU_TARGET_NAME) \
		--no-fail-fast \
		--features release \
		--offline \
		|| \
		CARGO_HOME=$(PKG_BUILD_DIR)/.cargo \
		cargo build --release --target=$(GNU_TARGET_NAME) \
		--no-fail-fast \
		--features release \
	)
endef

define Package/scutclient-rs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(GNU_TARGET_NAME)/release/scutclient-rs $(1)/usr/bin/scutclient-rs

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/scutclient.init $(1)/etc/init.d/scutclient

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/scutclient.config $(1)/etc/config/scutclient
endef

define Package/scutclient-rs/conffiles
/etc/config/scutclient
endef

$(eval $(call BuildPackage,scutclient-rs))
