import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { NetworkNode, NodeStatus } from '../../types';
import { useWebSocket } from '../../context/WebSocketContext';
import { RotateCw, Shield, Radio } from 'lucide-react';

interface NetworkTopology3DProps {
  nodes: NetworkNode[];
  onSelectNode?: (node: NetworkNode) => void;
  selectedNodeId?: string | null;
  height?: string | number;
  interactive?: boolean;
}

interface Node3DMeta {
  node: NetworkNode;
  mesh: THREE.Mesh;
  glowMesh?: THREE.Mesh;
  labelSprite?: THREE.Sprite;
  position: THREE.Vector3;
}

interface ParticleFlow {
  curve: THREE.CatmullRomCurve3;
  progress: number;
  speed: number;
  color: number;
  size: number;
  isAttack: boolean;
}

export const NetworkTopology3D: React.FC<NetworkTopology3DProps> = ({
  nodes,
  onSelectNode,
  selectedNodeId,
  height = 420,
  interactive = true,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { activeAttacks, isConnected } = useWebSocket();

  const [hoveredNode, setHoveredNode] = useState<NetworkNode | null>(null);
  const [autoRotate, setAutoRotate] = useState<boolean>(true);
  const [activeParticleCount, setActiveParticleCount] = useState<number>(0);

  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const nodeMapRef = useRef<Map<string, Node3DMeta>>(new Map());
  const particleSystemRef = useRef<THREE.Points | null>(null);
  const particlesDataRef = useRef<ParticleFlow[]>([]);
  const animationFrameIdRef = useRef<number | null>(null);

  // Helper to get node color by status
  const getNodeColor = useCallback((status: NodeStatus | string): number => {
    switch (status?.toUpperCase()) {
      case 'CRITICAL':
      case 'COMPROMISED':
        return 0xef4444; // Red
      case 'HIGH':
      case 'SUSPICIOUS':
        return 0xf59e0b; // Amber / Orange
      case 'ISOLATED':
        return 0xa855f7; // Purple
      case 'HEALTHY':
      default:
        return 0x10b981; // Emerald Green
    }
  }, []);

  // Helper to create sprite labels
  const createTextLabel = (text: string, subtext: string, colorHex: string): THREE.Sprite => {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 128;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.fillStyle = 'rgba(7, 10, 18, 0.85)';
      ctx.strokeStyle = colorHex;
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.roundRect(4, 4, 248, 120, 16);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 24px system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(text, 128, 50);

      ctx.fillStyle = '#94a3b8';
      ctx.font = '18px monospace';
      ctx.fillText(subtext, 128, 90);
    }

    const texture = new THREE.CanvasTexture(canvas);
    const spriteMaterial = new THREE.SpriteMaterial({
      map: texture,
      transparent: true,
      depthTest: false,
    });
    const sprite = new THREE.Sprite(spriteMaterial);
    sprite.scale.set(3.2, 1.6, 1);
    return sprite;
  };

  // Build or rebuild Three.js scene
  useEffect(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth || 600;
    const heightPx = typeof height === 'number' ? height : container.clientHeight || 420;

    // 1. Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x07090e);
    scene.fog = new THREE.FogExp2(0x07090e, 0.015);
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(45, width / heightPx, 0.1, 1000);
    camera.position.set(0, 24, 38);
    cameraRef.current = camera;

    // 3. Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, heightPx);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. OrbitControls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxPolarAngle = Math.PI / 2 - 0.05; // Stay above ground
    controls.minDistance = 10;
    controls.maxDistance = 80;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 0.8;
    controlsRef.current = controls;

    // 5. Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x38bdf8, 2);
    dirLight.position.set(20, 40, 20);
    scene.add(dirLight);

    const pointLight = new THREE.PointLight(0x0284c7, 3, 60);
    pointLight.position.set(0, 15, 0);
    scene.add(pointLight);

    // 6. Cyber Grid Ground Plane
    const gridHelper = new THREE.GridHelper(60, 40, 0x0284c7, 0x1e293b);
    gridHelper.position.y = -4;
    scene.add(gridHelper);

    // 7. Render Nodes
    const nodeMap = new Map<string, Node3DMeta>();
    const nodePositions: { [ip: string]: THREE.Vector3 } = {};

    nodes.forEach((node, idx) => {
      // Calculate 3D position
      let x = node.posX * 2.2;
      let y = node.posY * 1.5;
      let z = node.posZ * 2.2;

      // Fallback layout if database coords are all 0
      if (x === 0 && y === 0 && z === 0) {
        const angle = (idx / nodes.length) * Math.PI * 2;
        const radius = node.nodeType === 'FIREWALL' ? 0 : node.nodeType === 'ROUTER' ? 8 : 16;
        x = Math.cos(angle) * radius;
        y = node.nodeType === 'DB_SERVER' ? 2 : node.nodeType === 'ATTACKER' ? -1 : 0;
        z = Math.sin(angle) * radius;
      }

      const position = new THREE.Vector3(x, y, z);
      nodePositions[node.ipAddress] = position;
      nodePositions[node.id] = position;

      // Sphere Geometry
      const radius =
        node.nodeType === 'FIREWALL'
          ? 1.4
          : node.nodeType === 'ROUTER'
          ? 1.2
          : node.nodeType === 'DB_SERVER' || node.nodeType === 'WEB_SERVER'
          ? 1.1
          : 0.9;

      const geometry = new THREE.SphereGeometry(radius, 32, 32);
      const color = getNodeColor(node.status);

      const material = new THREE.MeshStandardMaterial({
        color: color,
        emissive: color,
        emissiveIntensity: node.status === 'COMPROMISED' ? 0.7 : node.status === 'SUSPICIOUS' ? 0.5 : 0.25,
        roughness: 0.2,
        metalness: 0.8,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.copy(position);
      mesh.userData = { node };
      scene.add(mesh);

      // Outer glow aura for threat nodes
      let glowMesh: THREE.Mesh | undefined;
      if (node.status === 'COMPROMISED' || node.status === 'SUSPICIOUS' || node.status === 'ISOLATED') {
        const glowGeo = new THREE.RingGeometry(radius * 1.3, radius * 1.6, 32);
        const glowMat = new THREE.MeshBasicMaterial({
          color: color,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.6,
        });
        glowMesh = new THREE.Mesh(glowGeo, glowMat);
        glowMesh.position.copy(position);
        glowMesh.rotation.x = Math.PI / 2;
        scene.add(glowMesh);
      }

      // Billboard Text Label
      const labelSprite = createTextLabel(
        node.label,
        node.ipAddress,
        node.status === 'COMPROMISED'
          ? '#ef4444'
          : node.status === 'SUSPICIOUS'
          ? '#f59e0b'
          : '#38bdf8'
      );
      labelSprite.position.set(position.x, position.y + radius + 1.6, position.z);
      scene.add(labelSprite);

      nodeMap.set(node.id, {
        node,
        mesh,
        glowMesh,
        labelSprite,
        position,
      });
    });

    nodeMapRef.current = nodeMap;

    // 8. Render Network Edges (Connections)
    const lineMaterial = new THREE.LineBasicMaterial({
      color: 0x0284c7,
      transparent: true,
      opacity: 0.35,
    });

    const edgeCurves: THREE.CatmullRomCurve3[] = [];

    // Derive logical subnet connections
    const nodeArray = Array.from(nodeMap.values());
    const firewallNode = nodeArray.find((n) => n.node.nodeType === 'FIREWALL') || nodeArray[0];

    nodeArray.forEach((source) => {
      nodeArray.forEach((target) => {
        if (source.node.id === target.node.id) return;

        let shouldConnect = false;

        // Subnet / Topology connectivity rules
        if (
          (source.node.nodeType === 'FIREWALL' && (target.node.nodeType === 'ROUTER' || target.node.nodeType === 'WEB_SERVER')) ||
          (source.node.nodeType === 'ROUTER' && (target.node.nodeType === 'WORKSTATION' || target.node.nodeType === 'AUTH_SERVER')) ||
          (source.node.nodeType === 'WEB_SERVER' && target.node.nodeType === 'DB_SERVER') ||
          (source.node.nodeType === 'ATTACKER' && target.node.id === firewallNode?.node.id)
        ) {
          shouldConnect = true;
        }

        if (shouldConnect) {
          const midPoint = new THREE.Vector3()
            .addVectors(source.position, target.position)
            .multiplyScalar(0.5);
          midPoint.y += 1.2; // slight arch

          const curve = new THREE.CatmullRomCurve3([source.position, midPoint, target.position]);
          edgeCurves.push(curve);

          const points = curve.getPoints(24);
          const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
          const line = new THREE.Line(lineGeo, lineMaterial);
          scene.add(line);
        }
      });
    });

    // 9. Particle Flow System for Live Traffic
    const particlesCount = 200;
    const particlePositions = new Float32Array(particlesCount * 3);
    const particleColors = new Float32Array(particlesCount * 3);

    const particlesGeo = new THREE.BufferGeometry();
    particlesGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    particlesGeo.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));

    const particlesMat = new THREE.PointsMaterial({
      size: 0.6,
      vertexColors: true,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
    });

    const particleSystem = new THREE.Points(particlesGeo, particlesMat);
    scene.add(particleSystem);
    particleSystemRef.current = particleSystem;

    // Initialize particle paths
    const particlesData: ParticleFlow[] = [];
    for (let i = 0; i < particlesCount; i++) {
      if (edgeCurves.length > 0) {
        const curve = edgeCurves[i % edgeCurves.length];
        particlesData.push({
          curve,
          progress: Math.random(),
          speed: 0.003 + Math.random() * 0.004,
          color: 0x38bdf8,
          size: 0.5,
          isAttack: false,
        });
      }
    }
    particlesDataRef.current = particlesData;
    setActiveParticleCount(particlesData.length);

    // 10. Raycasting for Click & Hover
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handlePointerMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const meshes = Array.from(nodeMap.values()).map((n) => n.mesh);
      const intersects = raycaster.intersectObjects(meshes);

      if (intersects.length > 0) {
        const found = intersects[0].object.userData.node as NetworkNode;
        setHoveredNode(found);
        container.style.cursor = 'pointer';
      } else {
        setHoveredNode(null);
        container.style.cursor = 'default';
      }
    };

    const handleClick = () => {
      raycaster.setFromCamera(mouse, camera);
      const meshes = Array.from(nodeMap.values()).map((n) => n.mesh);
      const intersects = raycaster.intersectObjects(meshes);

      if (intersects.length > 0) {
        const found = intersects[0].object.userData.node as NetworkNode;
        if (onSelectNode) onSelectNode(found);
      }
    };

    if (interactive) {
      container.addEventListener('mousemove', handlePointerMove);
      container.addEventListener('click', handleClick);
    }

    // 11. Responsive Resize Handler
    const handleResize = () => {
      if (!containerRef.current || !renderer || !camera) return;
      const newWidth = containerRef.current.clientWidth;
      const newHeight = typeof height === 'number' ? height : containerRef.current.clientHeight || 420;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    // 12. Main Animation Loop
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameIdRef.current = requestAnimationFrame(animate);
      clock.getDelta();
      const elapsedTime = clock.getElapsedTime();

      // Update Controls
      controls.update();

      // Pulse Glow Rings & highlight selected node
      nodeMap.forEach((meta) => {
        if (selectedNodeId && meta.node.id === selectedNodeId) {
          const s = 1.1 + Math.sin(elapsedTime * 6) * 0.1;
          meta.mesh.scale.set(s, s, s);
        }
        if (meta.glowMesh) {
          const s = 1 + Math.sin(elapsedTime * 4) * 0.15;
          meta.glowMesh.scale.set(s, s, s);
        }
      });

      // Update Traffic Flow Particles
      if (particleSystemRef.current && particlesDataRef.current.length > 0) {
        const posAttr = particleSystemRef.current.geometry.attributes.position as THREE.BufferAttribute;
        const colAttr = particleSystemRef.current.geometry.attributes.color as THREE.BufferAttribute;
        const colorObj = new THREE.Color();

        particlesDataRef.current.forEach((p, idx) => {
          p.progress += p.speed;
          if (p.progress > 1) p.progress = 0;

          const point = p.curve.getPoint(p.progress);
          posAttr.setXYZ(idx, point.x, point.y, point.z);

          colorObj.setHex(p.color);
          colAttr.setXYZ(idx, colorObj.r, colorObj.g, colorObj.b);
        });

        posAttr.needsUpdate = true;
        colAttr.needsUpdate = true;
      }

      renderer.render(scene, camera);
    };

    animate();

    // Cleanup
    return () => {
      if (animationFrameIdRef.current) cancelAnimationFrame(animationFrameIdRef.current);
      if (interactive) {
        container.removeEventListener('mousemove', handlePointerMove);
        container.removeEventListener('click', handleClick);
      }
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [nodes, height, interactive, autoRotate, getNodeColor, onSelectNode]);

  // React to Realtime Attacks: Spawn dynamic attack particles and highlight victim nodes!
  useEffect(() => {
    if (!activeAttacks || activeAttacks.length === 0 || !sceneRef.current) return;

    const latestAttack = activeAttacks[0];
    const nodeMap = nodeMapRef.current;

    // Find source and destination node 3D positions
    let srcMeta: Node3DMeta | undefined;
    let dstMeta: Node3DMeta | undefined;

    nodeMap.forEach((meta) => {
      if (meta.node.ipAddress === latestAttack.sourceIp) srcMeta = meta;
      if (meta.node.ipAddress === latestAttack.destinationIp) dstMeta = meta;
    });

    if (srcMeta && dstMeta) {
      // Highlight victim node
      const mat = dstMeta.mesh.material as THREE.MeshStandardMaterial;
      mat.color.setHex(0xef4444);
      mat.emissive.setHex(0xef4444);
      mat.emissiveIntensity = 0.9;

      // Update particle colors on this edge to intense red/orange
      particlesDataRef.current.forEach((p) => {
        if (Math.random() < 0.3) {
          p.color = 0xef4444;
          p.speed = 0.012; // High velocity attack burst
        }
      });
    }
  }, [activeAttacks]);

  // Reset Camera View
  const handleResetCamera = () => {
    if (cameraRef.current && controlsRef.current) {
      cameraRef.current.position.set(0, 24, 38);
      controlsRef.current.target.set(0, 0, 0);
      controlsRef.current.update();
    }
  };

  return (
    <div className="relative w-full overflow-hidden rounded-xl border border-cyan-900/60 bg-[#07090e]">
      {/* Three.js Canvas Container */}
      <div
        ref={containerRef}
        style={{ width: '100%', height: typeof height === 'number' ? `${height}px` : height }}
      />

      {/* Floating HUD Top Overlay */}
      <div className="absolute top-3 left-3 right-3 flex items-center justify-between pointer-events-none">
        <div className="flex items-center gap-2 bg-black/70 backdrop-blur-md px-3 py-1.5 rounded-lg border border-cyan-900/60 pointer-events-auto">
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
              }`}
            />
            <Radio size={13} className="text-cyan-400" />
            <span className="text-[11px] font-mono text-cyan-300">
              {isConnected ? 'LIVE WEBSOCKET STREAM' : 'OFFLINE'}
            </span>
          </div>
          <span className="text-slate-600 font-mono text-xs">|</span>
          <span className="text-[10px] text-slate-300 font-mono">
            {nodes.length} NODES &bull; {activeParticleCount} FLOW PARTICLES
          </span>
        </div>

        {/* Controls Overlay */}
        <div className="flex items-center gap-2 pointer-events-auto">
          <button
            type="button"
            className={`px-2.5 py-1 text-xs font-mono rounded border transition-all ${
              autoRotate
                ? 'bg-cyan-950/70 border-cyan-400 text-cyan-300'
                : 'bg-slate-900/80 border-slate-700 text-slate-400'
            }`}
            onClick={() => {
              setAutoRotate((prev) => !prev);
              if (controlsRef.current) controlsRef.current.autoRotate = !autoRotate;
            }}
          >
            {autoRotate ? 'Auto-Rotate ON' : 'Rotate OFF'}
          </button>
          <button
            type="button"
            className="p-1.5 bg-slate-900/80 hover:bg-slate-800 border border-slate-700 rounded text-slate-300 transition-all"
            onClick={handleResetCamera}
            title="Reset Camera Orientation"
          >
            <RotateCw size={14} />
          </button>
        </div>
      </div>

      {/* Hovered Node Tooltip HUD */}
      {hoveredNode && (
        <div className="absolute bottom-3 left-3 bg-slate-950/90 backdrop-blur-md p-3 rounded-lg border border-cyan-500/60 shadow-xl pointer-events-none max-w-xs animate-fadeIn">
          <div className="flex items-center gap-2 mb-1">
            <Shield size={14} className="text-cyan-400" />
            <span className="font-bold text-xs text-slate-100">{hoveredNode.label}</span>
            <span className="text-[10px] text-cyan-400 font-mono">({hoveredNode.nodeType})</span>
          </div>
          <div className="text-[11px] font-mono text-slate-300 space-y-0.5">
            <div>IP: <span className="text-cyan-300">{hoveredNode.ipAddress}</span></div>
            <div>Subnet: <span className="text-slate-400">{hoveredNode.subnet || 'N/A'}</span></div>
            <div>
              Status:{' '}
              <span
                className={
                  hoveredNode.status === 'COMPROMISED'
                    ? 'text-red-400 font-bold'
                    : hoveredNode.status === 'SUSPICIOUS'
                    ? 'text-amber-400 font-bold'
                    : 'text-emerald-400'
                }
              >
                {hoveredNode.status}
              </span>
            </div>
            {hoveredNode.openPorts && (
              <div className="text-[10px] text-slate-400">Ports: {hoveredNode.openPorts}</div>
            )}
          </div>
        </div>
      )}

      {/* Active Threat Toast Indicator */}
      {activeAttacks.length > 0 && (
        <div className="absolute bottom-3 right-3 bg-red-950/90 backdrop-blur-md px-3 py-2 rounded-lg border border-red-500/80 shadow-2xl pointer-events-none animate-pulse">
          <div className="flex items-center gap-2 text-xs font-bold text-red-300 font-mono">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span>ATTACK IN PROGRESS: {activeAttacks[0].threatType}</span>
          </div>
          <div className="text-[10px] text-slate-300 font-mono mt-0.5">
            {activeAttacks[0].sourceIp} &rarr; {activeAttacks[0].destinationIp}
          </div>
        </div>
      )}
    </div>
  );
};
