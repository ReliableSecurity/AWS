// Enhanced Matrix Digital Rain with Hacker Effects
class EnhancedMatrixRain {
    constructor() {
        this.canvas = document.getElementById('matrix');
        this.ctx = this.canvas.getContext('2d');
        this.resizeCanvas();
        
        // Enhanced properties
        this.fontSize = 14;
        this.columns = Math.floor(this.canvas.width / this.fontSize);
        this.drops = [];
        this.effects = [];
        
        // Hacker-style characters (more extensive)
        this.matrixChars = '0123456789ABCDEFアカサタナハマヤラワガザダバパイキシチニヒミリウィグズヅブプエケセテネヘメレヱゲゼデベペオコソトノホモヨロヲゴゾドボポヴッン'.split('');
        this.hackChars = '!@#$%^&*()_+-={}[]|\\:";\'<>?,./>?'.split('');
        this.binaryChars = '01'.split('');
        
        // Initialize drops
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.floor(Math.random() * this.canvas.height / this.fontSize);
        }
        
        // Bind events
        window.addEventListener('resize', () => this.resizeCanvas());
        this.canvas.addEventListener('mousemove', (e) => this.addMouseEffect(e));
        this.canvas.addEventListener('click', (e) => this.addClickEffect(e));
        
        // Start effects
        this.startMatrix();
        this.startGlitchEffect();
        this.startScanLines();
    }
    
    resizeCanvas() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.columns = Math.floor(this.canvas.width / this.fontSize);
    }
    
    getRandomChar() {
        const rand = Math.random();
        if (rand < 0.7) return this.matrixChars[Math.floor(Math.random() * this.matrixChars.length)];
        if (rand < 0.9) return this.binaryChars[Math.floor(Math.random() * this.binaryChars.length)];
        return this.hackChars[Math.floor(Math.random() * this.hackChars.length)];
    }
    
    drawMatrix() {
        // Semi-transparent black for trail effect
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.ctx.font = `${this.fontSize}px 'Courier New', monospace`;
        
        for (let i = 0; i < this.drops.length; i++) {
            // Random intensity for each column
            const intensity = Math.random();
            
            if (intensity > 0.95) {
                // Bright green lead character
                this.ctx.fillStyle = '#00ff41';
            } else if (intensity > 0.7) {
                // Medium green
                this.ctx.fillStyle = '#00aa00';
            } else {
                // Dark green
                this.ctx.fillStyle = '#004400';
            }
            
            const char = this.getRandomChar();
            const x = i * this.fontSize;
            const y = this.drops[i] * this.fontSize;
            
            this.ctx.fillText(char, x, y);
            
            // Add glow effect for bright characters
            if (intensity > 0.9) {
                this.ctx.shadowColor = '#00ff41';
                this.ctx.shadowBlur = 5;
                this.ctx.fillText(char, x, y);
                this.ctx.shadowBlur = 0;
            }
            
            // Reset drop to top when it reaches bottom
            if (this.drops[i] * this.fontSize > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            
            this.drops[i]++;
        }
    }
    
    addMouseEffect(e) {
        const rect = this.canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        // Create ripple effect at mouse position
        this.effects.push({
            type: 'ripple',
            x: x,
            y: y,
            radius: 0,
            maxRadius: 100,
            life: 1.0,
            decay: 0.02
        });
    }
    
    addClickEffect(e) {
        const rect = this.canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        // Create explosion effect at click
        for (let i = 0; i < 20; i++) {
            this.effects.push({
                type: 'particle',
                x: x + (Math.random() - 0.5) * 20,
                y: y + (Math.random() - 0.5) * 20,
                vx: (Math.random() - 0.5) * 10,
                vy: (Math.random() - 0.5) * 10,
                life: 1.0,
                decay: 0.03,
                char: this.getRandomChar()
            });
        }
        
        // Create EMP wave
        this.effects.push({
            type: 'emp',
            x: x,
            y: y,
            radius: 0,
            maxRadius: 200,
            life: 1.0,
            decay: 0.05
        });
    }
    
    drawEffects() {
        this.effects = this.effects.filter(effect => {
            effect.life -= effect.decay;
            
            if (effect.type === 'ripple') {
                effect.radius += 3;
                
                this.ctx.strokeStyle = `rgba(0, 255, 65, ${effect.life * 0.5})`;
                this.ctx.lineWidth = 2;
                this.ctx.beginPath();
                this.ctx.arc(effect.x, effect.y, effect.radius, 0, Math.PI * 2);
                this.ctx.stroke();
                
                return effect.life > 0 && effect.radius < effect.maxRadius;
            }
            
            if (effect.type === 'particle') {
                effect.x += effect.vx;
                effect.y += effect.vy;
                effect.vx *= 0.98;
                effect.vy *= 0.98;
                
                this.ctx.fillStyle = `rgba(0, 255, 65, ${effect.life})`;
                this.ctx.font = '12px Courier New';
                this.ctx.fillText(effect.char, effect.x, effect.y);
                
                return effect.life > 0;
            }
            
            if (effect.type === 'emp') {
                effect.radius += 8;
                
                // EMP wave with distortion effect
                this.ctx.strokeStyle = `rgba(0, 255, 255, ${effect.life * 0.3})`;
                this.ctx.lineWidth = 3;
                this.ctx.beginPath();
                this.ctx.arc(effect.x, effect.y, effect.radius, 0, Math.PI * 2);
                this.ctx.stroke();
                
                // Inner pulse
                this.ctx.strokeStyle = `rgba(255, 255, 255, ${effect.life * 0.6})`;
                this.ctx.lineWidth = 1;
                this.ctx.beginPath();
                this.ctx.arc(effect.x, effect.y, effect.radius * 0.5, 0, Math.PI * 2);
                this.ctx.stroke();
                
                return effect.life > 0 && effect.radius < effect.maxRadius;
            }
            
            return false;
        });
    }
    
    startMatrix() {
        const animate = () => {
            this.drawMatrix();
            this.drawEffects();
            requestAnimationFrame(animate);
        };
        animate();
    }
    
    startGlitchEffect() {
        setInterval(() => {
            if (Math.random() < 0.05) {
                // Random glitch effect
                const glitchCount = Math.random() * 5;
                for (let i = 0; i < glitchCount; i++) {
                    const x = Math.random() * this.canvas.width;
                    const y = Math.random() * this.canvas.height;
                    const width = Math.random() * 100;
                    const height = Math.random() * 20;
                    
                    // Save current state
                    this.ctx.save();
                    
                    // Apply distortion
                    this.ctx.fillStyle = `rgba(255, 0, 0, ${Math.random() * 0.3})`;
                    this.ctx.fillRect(x, y, width, height);
                    
                    this.ctx.fillStyle = `rgba(0, 255, 0, ${Math.random() * 0.3})`;
                    this.ctx.fillRect(x + 2, y, width, height);
                    
                    this.ctx.fillStyle = `rgba(0, 0, 255, ${Math.random() * 0.3})`;
                    this.ctx.fillRect(x - 2, y, width, height);
                    
                    this.ctx.restore();
                }
            }
        }, 100);
    }
    
    startScanLines() {
        let scanY = 0;
        const animateScanLines = () => {
            // Horizontal scan line
            this.ctx.strokeStyle = 'rgba(0, 255, 65, 0.1)';
            this.ctx.lineWidth = 1;
            this.ctx.beginPath();
            this.ctx.moveTo(0, scanY);
            this.ctx.lineTo(this.canvas.width, scanY);
            this.ctx.stroke();
            
            scanY += 2;
            if (scanY > this.canvas.height) scanY = 0;
            
            requestAnimationFrame(animateScanLines);
        };
        animateScanLines();
    }
}

// Terminal Typing Effect
class TerminalTypewriter {
    constructor(element, text, speed = 50) {
        this.element = element;
        this.text = text;
        this.speed = speed;
        this.index = 0;
        this.isBlinking = true;
        
        this.type();
        this.startCursor();
    }
    
    type() {
        if (this.index < this.text.length) {
            this.element.textContent += this.text.charAt(this.index);
            this.index++;
            setTimeout(() => this.type(), this.speed + Math.random() * 50);
        }
    }
    
    startCursor() {
        const cursor = document.createElement('span');
        cursor.className = 'terminal-cursor';
        cursor.textContent = '█';
        this.element.appendChild(cursor);
        
        setInterval(() => {
            cursor.style.opacity = cursor.style.opacity === '0' ? '1' : '0';
        }, 500);
    }
}

// Hacker Stats Animation
class HackerStatsAnimation {
    constructor() {
        this.animateCounters();
        this.startRandomFlicker();
    }
    
    animateCounters() {
        const counters = document.querySelectorAll('.stat-content h3');
        counters.forEach(counter => {
            const target = parseInt(counter.textContent) || 0;
            const increment = target / 20;
            let current = 0;
            
            const updateCounter = () => {
                if (current < target) {
                    current += increment;
                    counter.textContent = Math.ceil(current);
                    setTimeout(updateCounter, 100);
                } else {
                    counter.textContent = target;
                }
            };
            
            updateCounter();
        });
    }
    
    startRandomFlicker() {
        setInterval(() => {
            const elements = document.querySelectorAll('.stat-card, .scan-card');
            if (elements.length > 0 && Math.random() < 0.1) {
                const randomElement = elements[Math.floor(Math.random() * elements.length)];
                randomElement.style.boxShadow = '0 0 20px rgba(0, 255, 0, 0.8)';
                setTimeout(() => {
                    randomElement.style.boxShadow = '';
                }, 200);
            }
        }, 1000);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new EnhancedMatrixRain();
    new HackerStatsAnimation();
    
    // Add terminal typing effect to page titles
    const pageTitle = document.querySelector('h1');
    if (pageTitle && pageTitle.textContent) {
        const originalText = pageTitle.textContent;
        pageTitle.textContent = '';
        new TerminalTypewriter(pageTitle, originalText);
    }
});

// Add CSS for new effects
const style = document.createElement('style');
style.textContent = `
    .terminal-cursor {
        color: #00ff00;
        animation: blink 1s infinite;
    }
    
    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0; }
    }
    
    .notification-card {
        background: rgba(0, 0, 0, 0.8);
        border: 2px solid #00ff00;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 1rem;
        transition: all 0.3s ease;
        animation: slideInFromRight 0.5s ease-out;
    }
    
    .notification-card:hover {
        border-color: #ffffff;
        box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        transform: translateX(10px);
    }
    
    .notification-icon {
        font-size: 2rem;
        flex-shrink: 0;
    }
    
    .notification-content h3 {
        color: #00ff00;
        margin: 0 0 0.5rem 0;
    }
    
    .notification-content p {
        color: #ffffff;
        margin: 0 0 0.5rem 0;
        line-height: 1.4;
    }
    
    .notification-time {
        color: #888;
        font-size: 0.8rem;
    }
    
    @keyframes slideInFromRight {
        from {
            opacity: 0;
            transform: translateX(50px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .scan-card, .stat-card {
        transition: all 0.3s ease;
    }
    
    .scan-card:hover, .stat-card:hover {
        transform: translateY(-5px);
    }
    
    .progress-fill {
        background: linear-gradient(90deg, #00ff00, #ffffff, #00ffff) !important;
        animation: progressGlow 2s ease-in-out infinite alternate;
    }
    
    @keyframes progressGlow {
        from { box-shadow: 0 0 5px rgba(0, 255, 0, 0.5); }
        to { box-shadow: 0 0 15px rgba(0, 255, 255, 0.8); }
    }
`;
document.head.appendChild(style);
