module.exports = {
    content: [
        "./internal/web/**/*.templ",  // Your templ components
        "./internal/web/**/*.go",     // Go handlers if they include inline HTML // maybe not needed
    ],
    theme: {
        extend: {},
    },
    plugins: [],
}