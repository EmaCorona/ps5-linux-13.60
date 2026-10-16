# Clang 21, matching the toolchain the CI installs (apt.llvm.org llvm.sh 21).
# The image's clang is what the payload is actually compiled with: the SDK is a
# set of shims and `LLVM_CONFIG` resolves down to `clang` on PATH. See
# docs/TOOLCHAIN.md.
FROM silkeh/clang:21-trixie AS build
WORKDIR /deps

RUN set -eux; \
    apt-get update; \
    case "$(dpkg --print-architecture)" in \
      amd64) pkgs="gcc libc6-dev" ;; \
      *)     pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
    esac; \
    apt-get install -y --no-install-recommends $pkgs binutils make unzip wget python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    x86_64-linux-gnu-gcc --version

# pLabs5-SDK is pinned to a commit and the archive is checksummed. It supplies
# LLVM_CONFIG, which resolves to whichever LLVM the build then uses, so tracking
# a moving branch would silently change the produced ELF.
ARG PLABS5_SDK_COMMIT=eeae9d047623f71dbaecc7328dd4e32e4d7101d0
RUN wget -O plabs5.zip "https://codeload.github.com/pLabs5/pLabs5-SDK/zip/${PLABS5_SDK_COMMIT}"
RUN echo "48c4abb8c172ae4487f8cd485a682a7d4098304c676491caaa895b5a323d6feb  plabs5.zip" \
    | sha256sum --check -
RUN unzip plabs5.zip \
    && ln -s "pLabs5-SDK-${PLABS5_SDK_COMMIT}" pLabs5-SDK

RUN wget -O p5sdk.zip "https://github.com/ps5-payload-dev/sdk/releases/download/v0.44/ps5-payload-sdk.zip"
RUN echo "4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0  p5sdk.zip" | sha256sum --check -
RUN unzip p5sdk.zip

ENV LLVM_CONFIG="/deps/pLabs5-SDK/tools/nixos/llvm-config"
ENV PS5_PAYLOAD_SDK="/deps/ps5-payload-sdk"

WORKDIR /app
COPY . .
RUN make -j4

# Stamp the artifact with the manifest version, so the file name, the release
# name and kManifest.version cannot drift apart. `make version` reads the same
# field from source/manifest/manifest.c.
RUN set -eux; \
    ver="$(make -s version)"; \
    test -n "$ver"; \
    mkdir -p dist; \
    cp bin/pLinux5-NG.elf "dist/pLinux5-NG-${ver}.elf"; \
    cp bin/pLinux5-NG.elf dist/pLinux5-NG.elf; \
    sha256sum dist/pLinux5-NG.elf > dist/pLinux5-NG.elf.sha256

FROM scratch AS final
COPY --from=build /app/dist/ /
