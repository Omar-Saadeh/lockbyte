// script.js - Enhanced version with better structure and functionality

document.addEventListener('DOMContentLoaded', () => {
    // Configuration
    const config = {
        stars: {
            count: 300,
            minSize: 1,
            maxSize: 3,
            minDuration: 2,
            maxDuration: 5
        },
        news: {
            maxArticles: 5,
            apiUrl: 'https://api.example.com/news' // Replace with your actual API endpoint
        }
    };

    // DOM Elements
    const elements = {
        background: document.querySelector('.background'),
        starsContainer: document.querySelector('.stars'),
        newsContainer: document.getElementById('newsContainer'),
        loginForm: document.getElementById('loginForm'),
        video: document.querySelector('video'),
        fileInput: document.getElementById('file'),
        scanForms: document.querySelectorAll('.scan-form')
    };

    // Starfield Functions
    function createStars() {
        if (!elements.starsContainer) return;

        elements.starsContainer.innerHTML = '';
        for (let i = 0; i < config.stars.count; i++) {
            const star = document.createElement('div');
            star.classList.add('star');
            star.style.top = `${Math.random() * 100}%`;
            star.style.left = `${Math.random() * 100}%`;

            const size = Math.random() * (config.stars.maxSize - config.stars.minSize) + config.stars.minSize;
            star.style.width = `${size}px`;
            star.style.height = `${size}px`;

            const duration = Math.random() * (config.stars.maxDuration - config.stars.minDuration) + config.stars.minDuration;
            star.style.animationDuration = `${duration}s`;
            star.style.animationDelay = `${Math.random() * 5}s`;

            elements.starsContainer.appendChild(star);
        }
    }

    function animateStars() {
        const stars = document.querySelectorAll('.star');
        stars.forEach(star => {
            star.style.animationDuration = `${Math.random() * (config.stars.maxDuration - config.stars.minDuration) + config.stars.minDuration}s`;
        });
    }

    // News Functions
    adocument.addEventListener('DOMContentLoaded', function() {
    // Filter articles by source
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Update active button
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            const source = this.dataset.source;
            const articles = document.querySelectorAll('.news-card');
            
            articles.forEach(article => {
                if (source === 'all' || article.dataset.source === source) {
                    article.style.display = 'block';
                } else {
                    article.style.display = 'none';
                }
            });
        });
    });
    
    // Search functionality
    const searchInput = document.getElementById('newsSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const articles = document.querySelectorAll('.news-card');
            
            articles.forEach(article => {
                const title = article.querySelector('h3').textContent.toLowerCase();
                const summary = article.querySelector('.summary').textContent.toLowerCase();
                
                if (title.includes(searchTerm) || summary.includes(searchTerm)) {
                    article.style.display = 'block';
                } else {
                    article.style.display = 'none';
                }
            });
        });
    }
    
    // Bookmark functionality
    const bookmarkButtons = document.querySelectorAll('.bookmark-btn');
    bookmarkButtons.forEach(button => {
        button.addEventListener('click', function() {
            this.classList.toggle('saved');
            const articleId = this.dataset.articleId;
            
            // Save to localStorage
            const savedArticles = JSON.parse(localStorage.getItem('savedArticles') || '[]');
            const index = savedArticles.indexOf(articleId);
            
            if (index === -1) {
                savedArticles.push(articleId);
                this.innerHTML = '<i class="fas fa-bookmark"></i> Saved';
            } else {
                savedArticles.splice(index, 1);
                this.innerHTML = '<i class="far fa-bookmark"></i> Save';
            }
            
            localStorage.setItem('savedArticles', JSON.stringify(savedArticles));
        });
    });
    
    // Check for saved articles on load
    if (localStorage.getItem('savedArticles')) {
        const savedArticles = JSON.parse(localStorage.getItem('savedArticles'));
        savedArticles.forEach(id => {
            const btn = document.querySelector(`.bookmark-btn[data-article-id="${id}"]`);
            if (btn) {
                btn.classList.add('saved');
                btn.innerHTML = '<i class="fas fa-bookmark"></i> Saved';
            }
        });
    }
    
    // Retry fetch button
    const retryBtn = document.getElementById('retryFetch');
    if (retryBtn) {
        retryBtn.addEventListener('click', function() {
            window.location.reload();
        });
    }
    
    // Newsletter form
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = this.querySelector('input').value;
            
            // Simple validation
            if (email && email.includes('@')) {
                alert(`Thank you for subscribing with ${email}! You'll receive our next security newsletter.`);
                this.reset();
            } else {
                alert('Please enter a valid email address.');
            }
        });
    }
});

    // Video Functions
    function initializeVideo() {
        if (!elements.video) return;

        const videoSources = [
            'assets/videos/intro.mp4',
            'assets/videos/intro.webm',
            'https://example.com/videos/intro.mp4'
        ];

        videoSources.forEach(src => {
            const source = document.createElement('source');
            source.src = src;
            source.type = `video/${src.split('.').pop()}`;
            elements.video.appendChild(source);
        });

        elements.video.innerHTML += `
            <p>Your browser does not support HTML5 video. Here is a <a href="${videoSources[0]}">link to the video</a> instead.</p>
        `;
    }

    // Login Form Handling
    function setupLoginForm() {
        if (!elements.loginForm) return;

        elements.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(elements.loginForm);
            const username = formData.get('username');
            const password = formData.get('password');

            if (!username || !password) {
                showAlert('Please fill in all fields', 'error');
                return;
            }

            try {
                showAlert('Login successful! Redirecting...', 'success');
                elements.loginForm.reset();
                setTimeout(() => {
                    window.location.href = 'profile.html';
                }, 1500);
            } catch (error) {
                showAlert('Login failed. Please try again.', 'error');
                console.error('Login error:', error);
            }
        });
    }

    // Malware Scanner JS (File Input + Form Handling)
    function setupMalwareScanner() {
        // File input styling
        if (elements.fileInput) {
            elements.fileInput.addEventListener('change', function (e) {
                const fileName = e.target.files[0] ? e.target.files[0].name : 'No file selected';
                const label = document.createElement('span');
                label.textContent = fileName;
                label.style.marginLeft = '10px';
                label.style.color = '#ddd';

                const existingLabel = elements.fileInput.nextElementSibling;
                if (existingLabel && existingLabel.tagName === 'SPAN') {
                    existingLabel.remove();
                }

                elements.fileInput.parentNode.insertBefore(label, elements.fileInput.nextSibling);
            });
        }

        // Form submission handlers
        elements.scanForms.forEach(form => {
            form.addEventListener('submit', function (e) {
                const submitBtn = this.querySelector('input[type="submit"]');
                if (submitBtn) {
                    submitBtn.value = "Scanning...";
                    submitBtn.disabled = true;
                }
            });
        });
    }

    // UI Helpers
    function showAlert(message, type = 'info') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        document.body.appendChild(alert);
        setTimeout(() => {
            alert.classList.add('fade-out');
            setTimeout(() => alert.remove(), 500);
        }, 3000);
    }

    // Parallax Effect
    function setupParallax() {
        if (!elements.starsContainer) return;
        window.addEventListener('mousemove', (e) => {
            const { clientX, clientY } = e;
            const centerX = window.innerWidth / 2;
            const centerY = window.innerHeight / 2;
            const stars = document.querySelectorAll('.star');

            stars.forEach(star => {
                const speed = parseFloat(star.style.animationDuration) * 0.5;
                const moveX = (clientX - centerX) / (centerX * speed);
                const moveY = (clientY - centerY) / (centerY * speed);
                star.style.transform = `translate(${moveX}px, ${moveY}px)`;
            });
        });
    }

    // Initialize all functionality
    function init() {
        createStars();
        setupParallax();
        fetchNewsArticles();
        initializeVideo();
        setupLoginForm();
        setupMalwareScanner();
        setInterval(animateStars, 10000);
        console.log('Application initialized');
    }

    // Start the application
    init();
});
