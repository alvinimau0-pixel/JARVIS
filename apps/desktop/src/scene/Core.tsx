import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import type { VisualState } from "../state/visual";
import { lookFor } from "./palette";

interface Props {
  state: VisualState;
  reducedMotion: boolean;
  lowPower: boolean;
}

function webglAvailable(): boolean {
  try {
    const c = document.createElement("canvas");
    return Boolean(c.getContext("webgl2") ?? c.getContext("webgl"));
  } catch {
    return false;
  }
}

/** The live JARVIS core. Rendering parameters are driven only by the derived visual state. */
export function Core({ state, reducedMotion, lowPower }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const stateRef = useRef(state);
  const motionRef = useRef({ reducedMotion, lowPower });
  const [supported] = useState(webglAvailable);

  useEffect(() => {
    stateRef.current = state;
  }, [state]);
  useEffect(() => {
    motionRef.current = { reducedMotion, lowPower };
  }, [reducedMotion, lowPower]);

  useEffect(() => {
    const el = host.current;
    if (!el || !supported) return;

    const renderer = new THREE.WebGLRenderer({ antialias: !lowPower, alpha: true, powerPreference: lowPower ? "low-power" : "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, lowPower ? 1 : 2));
    el.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
    camera.position.set(0, 0, 8.6); // keeps the outer ring inside the stage at any aspect

    const group = new THREE.Group();
    scene.add(group);

    const shellGeo = new THREE.IcosahedronGeometry(1.35, 1);
    const shellMat = new THREE.MeshBasicMaterial({ wireframe: true, transparent: true, opacity: 0.55 });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);

    const coreGeo = new THREE.SphereGeometry(0.55, 32, 32);
    const coreMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.9 });
    const core = new THREE.Mesh(coreGeo, coreMat);
    group.add(core);

    const haloGeo = new THREE.SphereGeometry(0.85, 32, 32);
    const haloMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false });
    group.add(new THREE.Mesh(haloGeo, haloMat));

    const rings: THREE.Mesh[] = [];
    const ringGeos: THREE.BufferGeometry[] = [];
    const ringMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.6, side: THREE.DoubleSide });
    [2.0, 2.35, 2.7].forEach((r, i) => {
      const g = new THREE.TorusGeometry(r, 0.008 + i * 0.002, 6, 160);
      ringGeos.push(g);
      const m = new THREE.Mesh(g, ringMat);
      m.rotation.x = 1.15 + i * 0.14; // tilted orbits, never edge-on
      m.rotation.y = (i - 1) * 0.45;
      rings.push(m);
      group.add(m);
    });

    const color = new THREE.Color(lookFor(stateRef.current).color); // start in the real state colour
    const resize = () => {
      const w = el.clientWidth || 1;
      const h = el.clientHeight || 1;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(el);
    resize();

    let raf = 0;
    let last = performance.now();
    let elapsed = 0;
    let lastFrame = 0;
    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      const { reducedMotion: rm, lowPower: lp } = motionRef.current;
      if (document.hidden) return; // never burn GPU in the background
      if (lp && now - lastFrame < 1000 / 30) return;
      lastFrame = now;
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      elapsed += dt;

      const look = lookFor(stateRef.current);
      color.lerp(new THREE.Color(look.color), Math.min(1, dt * 3));
      shellMat.color.copy(color);
      coreMat.color.copy(color);
      haloMat.color.copy(color);
      ringMat.color.copy(color);

      const pulse = look.pulse > 0 && !rm ? 0.5 + 0.5 * Math.sin(elapsed * Math.PI * 2 * look.pulse) : 1;
      coreMat.opacity = 0.35 + 0.6 * look.intensity * pulse;
      haloMat.opacity = 0.05 + 0.15 * look.intensity * pulse;
      if (!rm) {
        shell.rotation.y += look.spin * dt;
        shell.rotation.x += look.spin * 0.4 * dt;
        rings.forEach((ring, i) => (ring.rotation.z += look.spin * (0.6 + i * 0.25) * dt * (i % 2 ? -1 : 1)));
      }
      renderer.render(scene, camera);
    };
    raf = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      [shellGeo, coreGeo, haloGeo, ...ringGeos].forEach((g) => g.dispose());
      [shellMat, coreMat, haloMat, ringMat].forEach((m) => m.dispose());
      renderer.dispose();
      renderer.forceContextLoss();
      renderer.domElement.remove();
    };
    // Recreate the renderer only when the power profile changes.
  }, [supported, lowPower]);

  const look = lookFor(state);
  return (
    <div className="core" data-state={state} aria-hidden="true">
      <div ref={host} className="core-canvas" />
      {!supported && (
        <div className="core-fallback" style={{ borderColor: look.css, boxShadow: `0 0 40px ${look.css}55` }} />
      )}
    </div>
  );
}
