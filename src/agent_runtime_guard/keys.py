# -*- coding: utf-8 -*-
"""
keys.py — Ed25519 签名密钥管理

第二熔断层的每个裁决都由一把本地 Ed25519 密钥签名。密钥首次使用时
生成并落盘；公钥指纹 (kid) 写进每张收据，任何持有公钥的一方都能离线
复核裁决，无需信任被验证的 agent。

诚实边界：这是本地自持密钥 (self-generated)，提供的是 *可离线验证性* 与
*篡改可见性*，不是第三方 CA 身份背书。需要外部信任时，由组织把公钥登记
到自己的信任根。

文件：
    signing.key   私钥 (PKCS#8 PEM)，权限 0600
    verifying.pub 公钥 (SubjectPublicKeyInfo PEM)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_NAME = "signing.key"
PUBLIC_KEY_NAME = "verifying.pub"


class Signer:
    """持有 Ed25519 私钥，负责签名并暴露 kid / 公钥。"""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public = private_key.public_key()
        self._kid = self.compute_kid(self._public)

    # ------------------------------------------------------------------
    @property
    def kid(self) -> str:
        """公钥指纹：sha256(原始公钥字节) 前 16 hex。"""
        return self._kid

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def public_pem(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes) -> bytes:
        """对原始字节签名，返回 64 字节 Ed25519 签名。"""
        return self._private.sign(data)

    # ------------------------------------------------------------------
    @staticmethod
    def compute_kid(public_key: Ed25519PublicKey) -> str:
        import hashlib

        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw).hexdigest()[:16]

    # ------------------------------------------------------------------
    @classmethod
    def load_or_create(cls, keys_dir: os.PathLike[str] | str) -> "Signer":
        """加载目录中的私钥；不存在则生成新密钥对并落盘。

        Args:
            keys_dir: 密钥目录 (自动创建)。

        Returns:
            Signer。
        """
        directory = Path(keys_dir)
        directory.mkdir(parents=True, exist_ok=True)
        priv_path = directory / PRIVATE_KEY_NAME
        pub_path = directory / PUBLIC_KEY_NAME

        if priv_path.exists():
            private_key = serialization.load_pem_private_key(
                priv_path.read_bytes(), password=None
            )
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("signing.key is not an Ed25519 private key")
            signer = cls(private_key)
            # 始终把公钥补齐/对齐，便于离线分发
            if not pub_path.exists():
                pub_path.write_bytes(signer.public_pem())
            return signer

        private_key = Ed25519PrivateKey.generate()
        signer = cls(private_key)

        priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(signer.public_pem())
        try:
            priv_path.chmod(0o600)
        except OSError:
            # 某些文件系统不支持 chmod；密钥仍只位于用户目录
            pass
        return signer


def load_public_key(public_pem: bytes) -> Ed25519PublicKey:
    """从 PEM 读取 Ed25519 公钥 (供离线验证)。"""
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEM is not an Ed25519 public key")
    return key


def kid_from_public(public_key: Ed25519PublicKey) -> str:
    return Signer.compute_kid(public_key)
