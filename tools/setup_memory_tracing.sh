#!/bin/bash
# Setup memory tracing in Lime3DS emulator

set -e

EMULATOR_DIR="$(pwd)/build/emulator/Lime3DS"
PATCH_DIR="$(pwd)/tools/emulator_patches"

echo "Setting up memory tracing for Lime3DS..."

# Create patch directory
mkdir -p "$PATCH_DIR"

# Create memory tracing patch
cat > "$PATCH_DIR/memory_trace.patch" << 'EOF'
diff --git a/src/core/memory.cpp b/src/core/memory.cpp
index 1234567..abcdefg 100644
--- a/src/core/memory.cpp
+++ b/src/core/memory.cpp
@@ -1,6 +1,7 @@
 #include "core/memory.h"
 #include "common/logging/log.h"
 #include "core/hle/kernel/process.h"
+#include "core/arm/arm_interface.h"

 namespace Memory {

@@ -100,6 +101,15 @@ void Write8(const VAddr vaddr, const u8 data) {
         return;
     }

+#ifdef ENABLE_MEMORY_TRACING
+    // Trace writes to LINEAR_HEAP region where FPS flag lives
+    if (vaddr >= 0x30000000 && vaddr <= 0x30001000) {
+        u32 pc = Core::System::GetInstance().GetCurrentCore().GetPC();
+        LOG_WARNING(Memory, "[MEM_TRACE] Write8: PC={:08x} Addr={:08x} Val={:02x}",
+                    pc, vaddr, data);
+    }
+#endif
+
     // ... rest of function
 }

@@ -150,6 +160,15 @@ void Write16(const VAddr vaddr, const u16 data) {
         return;
     }

+#ifdef ENABLE_MEMORY_TRACING
+    if (vaddr >= 0x30000000 && vaddr <= 0x30001000) {
+        u32 pc = Core::System::GetInstance().GetCurrentCore().GetPC();
+        LOG_WARNING(Memory, "[MEM_TRACE] Write16: PC={:08x} Addr={:08x} Val={:04x}",
+                    pc, vaddr, data);
+    }
+#endif
+
     // ... rest of function
 }

@@ -200,6 +219,15 @@ void Write32(const VAddr vaddr, const u32 data) {
         return;
     }

+#ifdef ENABLE_MEMORY_TRACING
+    if (vaddr >= 0x30000000 && vaddr <= 0x30001000) {
+        u32 pc = Core::System::GetInstance().GetCurrentCore().GetPC();
+        LOG_WARNING(Memory, "[MEM_TRACE] Write32: PC={:08x} Addr={:08x} Val={:08x}",
+                    pc, vaddr, data);
+    }
+#endif
+
     // ... rest of function
 }
EOF

echo "Memory trace patch created at: $PATCH_DIR/memory_trace.patch"
echo ""
echo "To apply and build:"
echo "  cd $EMULATOR_DIR"
echo "  git apply $(pwd)/$PATCH_DIR/memory_trace.patch"
echo "  cd build"
echo "  cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_MEMORY_TRACING=ON"
echo "  make -j\$(nproc)"
echo ""
echo "To capture traces:"
echo "  export CITRA_LOG=memory:warning"
echo "  ./bin/citra-qt /path/to/rom.3ds 2>&1 | grep MEM_TRACE | tee memory_trace.log"
