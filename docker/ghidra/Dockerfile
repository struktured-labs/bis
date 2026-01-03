FROM eclipse-temurin:21-jdk

ARG GHIDRA_VERSION=11.2
ARG GHIDRA_GITHUB_TOKEN=""
ARG GHIDRA_BASE_URL=https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags

RUN apt-get update && apt-get install -y --no-install-recommends \
  curl unzip ca-certificates bash git jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN set -e; \
  # Try to find download URL from GitHub API
  for TAG_SUFFIX in "build" "PUBLIC"; do \
    TAG="Ghidra_${GHIDRA_VERSION}_${TAG_SUFFIX}"; \
    API_URL="${GHIDRA_BASE_URL}/${TAG}"; \
    echo "Trying: $API_URL"; \
    ASSET_URL=$(curl -fsSL "$API_URL" 2>/dev/null | tr -d '\000-\037' | jq -r '.assets[] | select(.name | test("^ghidra_.*PUBLIC.*\\.zip$")) | .browser_download_url' 2>/dev/null | head -n1); \
    if [ -n "$ASSET_URL" ] && [ "$ASSET_URL" != "null" ]; then break; fi; \
  done; \
  if [ -z "$ASSET_URL" ] || [ "$ASSET_URL" = "null" ]; then \
    echo "API lookup failed, using direct URL construction"; \
    ASSET_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_$(date +%Y)0620.zip"; \
  fi; \
  echo "Downloading $ASSET_URL"; \
  curl -fsSL -o ghidra.zip "$ASSET_URL" || { \
    echo "Trying alternative date formats..."; \
    for DATE in "20250620" "20250115" "20241201"; do \
      ALT_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${DATE}.zip"; \
      echo "Trying: $ALT_URL"; \
      curl -fsSL -o ghidra.zip "$ALT_URL" && break || true; \
    done; \
  }; \
  unzip -q ghidra.zip; \
  mv ghidra_*_PUBLIC ghidra; \
  rm ghidra.zip; \
  ls -1 ghidra

ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="$GHIDRA_HOME/support:$PATH"

# Default entrypoint just displays help; we override in make target
ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]