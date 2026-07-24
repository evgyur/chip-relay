(() => {
  "use strict";

  const GLOBAL_KEY = "__chipRelayProtectionSnapshot";
  const SCHEMA = "chip-relay-fingerprint-observer-v1";
  const LIFETIME_MS = 10000;
  const MAX_TOTAL = 1000;
  if (Object.prototype.hasOwnProperty.call(globalThis, GLOBAL_KEY)) return;

  const startedAt = Date.now();
  const counts = Object.create(null);
  const restorers = [];
  let active = true;
  let total = 0;
  let snapshot = null;

  function bump(name) {
    if (!active || total >= MAX_TOTAL) return;
    counts[name] = Math.min(1000, (counts[name] || 0) + 1);
    total += 1;
  }

  function wrapMethod(target, property, label) {
    if (!target) return;
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    if (!descriptor || typeof descriptor.value !== "function" || descriptor.configurable === false) return;
    const original = descriptor.value;
    const wrapped = function () {
      bump(label);
      return Reflect.apply(original, this, arguments);
    };
    try {
      Object.defineProperty(target, property, {...descriptor, value: wrapped});
      restorers.push(() => {
        const current = Object.getOwnPropertyDescriptor(target, property);
        if (current && current.value === wrapped) Object.defineProperty(target, property, descriptor);
      });
    } catch (_) {
      // Unsupported or frozen surface: leave it untouched.
    }
  }

  function wrapGetter(target, property, label) {
    if (!target) return;
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    if (!descriptor || typeof descriptor.get !== "function" || descriptor.configurable === false) return;
    const original = descriptor.get;
    const wrapped = function () {
      bump(label);
      return Reflect.apply(original, this, []);
    };
    try {
      Object.defineProperty(target, property, {...descriptor, get: wrapped});
      restorers.push(() => {
        const current = Object.getOwnPropertyDescriptor(target, property);
        if (current && current.get === wrapped) Object.defineProperty(target, property, descriptor);
      });
    } catch (_) {
      // Unsupported or frozen surface: leave it untouched.
    }
  }

  function restoreAll(removeSnapshot = false) {
    active = false;
    while (restorers.length) {
      try {
        restorers.pop()();
      } catch (_) {
        // A page mutation won the race; do not overwrite it.
      }
    }
    if (removeSnapshot && snapshot) {
      try {
        const current = Object.getOwnPropertyDescriptor(globalThis, GLOBAL_KEY);
        if (current && current.value === snapshot) delete globalThis[GLOBAL_KEY];
      } catch (_) {
        // Cleanup is best-effort after page-level mutation.
      }
    }
  }

  try {
    wrapMethod(globalThis.HTMLCanvasElement?.prototype, "toDataURL", "canvas.toDataURL");
  wrapMethod(globalThis.HTMLCanvasElement?.prototype, "toBlob", "canvas.toBlob");
  wrapMethod(globalThis.CanvasRenderingContext2D?.prototype, "getImageData", "canvas.getImageData");
  wrapMethod(globalThis.CanvasRenderingContext2D?.prototype, "measureText", "fonts.measureText");

  for (const prototype of [globalThis.WebGLRenderingContext?.prototype, globalThis.WebGL2RenderingContext?.prototype]) {
    wrapMethod(prototype, "getParameter", "webgl.getParameter");
    wrapMethod(prototype, "getExtension", "webgl.getExtension");
    wrapMethod(prototype, "readPixels", "webgl.readPixels");
  }

  wrapMethod(globalThis.AudioBuffer?.prototype, "getChannelData", "audio.getChannelData");
  wrapMethod(globalThis.AudioBuffer?.prototype, "copyFromChannel", "audio.copyFromChannel");
  wrapMethod(globalThis.AnalyserNode?.prototype, "getFloatFrequencyData", "audio.getFloatFrequencyData");
  wrapMethod(globalThis.AnalyserNode?.prototype, "getByteFrequencyData", "audio.getByteFrequencyData");

  wrapMethod(globalThis.FontFaceSet?.prototype, "check", "fonts.check");
  wrapMethod(globalThis.RTCPeerConnection?.prototype, "createOffer", "webrtc.createOffer");
  wrapMethod(globalThis.RTCPeerConnection?.prototype, "setLocalDescription", "webrtc.setLocalDescription");

  wrapGetter(globalThis.Navigator?.prototype, "hardwareConcurrency", "navigator.hardwareConcurrency");
  wrapGetter(globalThis.Navigator?.prototype, "deviceMemory", "navigator.deviceMemory");
  wrapGetter(globalThis.Navigator?.prototype, "languages", "navigator.languages");
  wrapGetter(globalThis.Navigator?.prototype, "webdriver", "navigator.webdriver");
  wrapGetter(globalThis.Navigator?.prototype, "plugins", "navigator.plugins");

  wrapMethod(globalThis.Storage?.prototype, "getItem", "storage.getItem");
  wrapMethod(globalThis.Storage?.prototype, "key", "storage.key");
  wrapMethod(globalThis.Performance?.prototype, "now", "performance.now");
  wrapMethod(globalThis.Performance?.prototype, "getEntriesByType", "performance.getEntriesByType");

  wrapGetter(globalThis.Screen?.prototype, "colorDepth", "screen.colorDepth");
  wrapGetter(globalThis.Screen?.prototype, "pixelDepth", "screen.pixelDepth");
  wrapGetter(globalThis.Screen?.prototype, "width", "screen.width");
    wrapGetter(globalThis.Screen?.prototype, "height", "screen.height");

    snapshot = () => ({
      schema: SCHEMA,
      mode: "instrumented",
      active,
      elapsed_ms: Math.max(0, Date.now() - startedAt),
      counts: Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right))),
    });
    Object.defineProperty(globalThis, GLOBAL_KEY, {
      configurable: true,
      enumerable: false,
      value: snapshot,
    });
    const schedule = globalThis.setTimeout;
    if (typeof schedule !== "function") throw new TypeError("setTimeout unavailable");
    Reflect.apply(schedule, globalThis, [restoreAll, LIFETIME_MS]);
  } catch (_) {
    restoreAll(true);
  }
})();
