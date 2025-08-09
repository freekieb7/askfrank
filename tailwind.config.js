module.exports = {
    content: [
        "./internal/web/**/*.templ",  // Your templ components
        "./internal/web/**/*.go",     // Go handlers if they include inline HTML
        "./internal/web/**/*.html",   // Any HTML files
    ],
    darkMode: 'class', // Enable class-based dark mode
    safelist: [
        // Ensure dark mode classes are included
        'dark:bg-gray-900',
        'dark:bg-gray-800',
        'dark:bg-gray-700',
        'dark:text-gray-100',
        'dark:text-gray-300',
        'dark:text-gray-400',
        'dark:text-gray-500',
        'dark:border-gray-700',
        'dark:hover:bg-gray-700',
        'dark:hover:text-gray-400',
        'dark:ring-gray-600',
        'dark:placeholder:text-gray-500',
        'dark:focus:bg-gray-600',
        'dark:focus:ring-aqua',
        'dark:text-aqua',
    ],
    theme: {
        extend: {
            colors: {
                // Healthcare-focused color palette
                primary: {
                    50: '#eff6ff',
                    100: '#dbeafe',
                    200: '#bfdbfe',
                    300: '#93c5fd',
                    400: '#60a5fa',
                    500: '#3b82f6',
                    600: '#2563eb',
                    700: '#1d4ed8',
                    800: '#1e40af',
                    900: '#1e3a8a',
                },
                medical: {
                    50: '#f0fdfa',
                    100: '#ccfbf1',
                    200: '#99f6e4',
                    300: '#5eead4',
                    400: '#2dd4bf',
                    500: '#14b8a6',
                    600: '#0d9488',
                    700: '#0f766e',
                    800: '#115e59',
                    900: '#134e4a',
                },
                // Custom gradients for healthcare
                'gradient-start': '#3b82f6',
                'gradient-end': '#6366f1',
            },
            fontFamily: {
                'sans': ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-in-out',
                'slide-up': 'slideUp 0.3s ease-out',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideUp: {
                    '0%': { transform: 'translateY(10px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' },
                },
            },
            boxShadow: {
                'soft': '0 2px 15px -3px rgba(0, 0, 0, 0.07), 0 10px 20px -2px rgba(0, 0, 0, 0.04)',
                'medical': '0 4px 6px -1px rgba(59, 130, 246, 0.1), 0 2px 4px -1px rgba(59, 130, 246, 0.06)',
            },
            borderRadius: {
                'xl': '0.75rem',
                '2xl': '1rem',
                '3xl': '1.5rem',
            },
        },
    },
    plugins: [],
}