# 🎨 UI Style Guide

This document defines the core color palette and usage guidelines for your UI based on the Tailwind configuration.

---

## 🌈 Color Palette

### 🩺 Primary Healthcare Colors (Blue Spectrum)
| Tailwind Class   | Hex       | Usage Recommendation                         |
|------------------|-----------|----------------------------------------------|
| `primary-500`    | `#3b82f6` | Primary buttons, headers, brand accent       |
| `primary-600`    | `#2563eb` | Hover states, active states                  |
| `primary-700`    | `#1d4ed8` | Pressed states, dark themes                  |
| `primary-400`    | `#60a5fa` | Light accents, disabled states               |

### 🧬 Medical Colors (Teal/Mint Spectrum)
| Tailwind Class   | Hex       | Usage Recommendation                         |
|------------------|-----------|----------------------------------------------|
| `medical-500`    | `#14b8a6` | Success states, call-to-actions              |
| `medical-600`    | `#0d9488` | Success hover states, icons                  |
| `medical-400`    | `#2dd4bf` | Highlights, badges, accents                  |
| `medical-300`    | `#5eead4` | Light accents, tags                          |

### 🎨 Gradient Colors
| Tailwind Class      | Hex       | Usage Recommendation                      |
|---------------------|-----------|------------------------------------------|
| `gradient-start`    | `#3b82f6` | Gradient backgrounds (from)              |
| `gradient-end`      | `#6366f1` | Gradient backgrounds (to)                |

---

## 🧱 Usage Guidelines

### 🎯 Primary Color – Primary Blue `primary-500`
- Use for navigation bars, primary action buttons, or branding highlights.
- Class examples: `bg-primary-500`, `text-primary-500`, `border-primary-500`
- Avoid overusing to preserve impact.

### 🧭 Secondary Color – Primary Blue Dark `primary-600`
- Ideal for button hovers, link hovers, or secondary UI elements.
- Class examples: `hover:bg-primary-600`, `focus:border-primary-600`
- Pairs well with primary-500 for subtle contrast.

### ✅ Accent Color – Medical Teal `medical-500`
- Great for success messages, form indicators, or badges.
- Class examples: `bg-medical-500`, `text-medical-500`

### 🔗 Supporting Accent – Medical Light `medical-400`
- Use for hyperlinks, borders, tags, or minor CTAs.
- Class examples: `text-medical-400`, `border-medical-400`

### 🌈 Gradient Backgrounds
- Use `from-gradient-start to-gradient-end` for hero sections and cards
- Example: `bg-linear-to-r from-gradient-start to-gradient-end`

---

## 📏 Layout & Spacing Guidelines

### 🏗️ Container Patterns
- **Page Containers**: Use `max-w-6xl` (1152px) for content-heavy pages like billing/pricing
- **Form Containers**: Use `max-w-2xl` (672px) for forms and narrow content
- **Card Grids**: Use `gap-6` (24px) for compact layouts, `gap-8` (32px) for spacious layouts

### 📦 Card Component Standards
- **Padding**: Use `p-5` (20px) for compact cards, `p-6` (24px) for standard cards
- **Margins**: Use `mb-6` (24px) between card sections, `mb-8` (32px) between major sections
- **Borders**: Use `border border-gray-200` for subtle card borders
- **Shadows**: Use `shadow-sm` for subtle depth, `shadow-lg` for emphasized cards

### 📝 Typography Hierarchy
- **Page Titles**: `text-2xl font-bold` for compact layouts, `text-3xl font-bold` for spacious
- **Section Headers**: `text-lg font-semibold` for compact, `text-xl font-semibold` for standard
- **Subsection Headers**: `text-base font-medium` for compact, `text-lg font-medium` for standard
- **Body Text**: `text-sm` for compact layouts, `text-base` for standard layouts
- **Supporting Text**: `text-xs` for compact, `text-sm` for standard

### 🎛️ Button & Interactive Element Guidelines
- **Primary Buttons**: `bg-primary-500 hover:bg-primary-600 text-white`
- **Secondary Buttons**: `bg-gray-200 hover:bg-gray-300 text-gray-900`
- **Success Buttons**: `bg-medical-500 hover:bg-medical-600 text-white`
- **Button Padding**: `py-2 px-4` for compact, `py-3 px-4` for standard
- **Button Text**: `text-sm font-medium` for compact, `text-base font-medium` for standard

### 📱 Responsive Grid Patterns
- **Pricing Cards**: `grid-cols-1 md:grid-cols-3` for 3-tier layouts
- **Info Sections**: `grid-cols-1 lg:grid-cols-2` for side-by-side content
- **Feature Lists**: Use `space-y-2` for compact lists, `space-y-3` for standard

### ✨ Special Component Patterns

#### 💳 Pricing Card Best Practices
- Use `scale-105 shadow-medical` for featured/popular plans
- Include "Most Popular" badge with `bg-primary-500 text-white` styling
- Use Medical Green checkmarks (`text-medical-500`) for included features
- Use gray X marks (`text-gray-400`) for excluded features
- Keep feature lists to 5-6 items maximum for readability

#### 🏷️ Status Indicators
- **Active/Success**: Use Medical Teal (`text-medical-500` or `bg-medical-500`)
- **Primary/Important**: Use Primary Blue (`text-primary-500` or `bg-primary-500`)
- **Warning/Pending**: Use appropriate warning colors
- **Inactive/Disabled**: Use `text-gray-400` or `bg-gray-100`

### 🖼️ Icon Guidelines
- **Standard Icons**: `w-4 h-4` for compact layouts, `w-5 h-5` for standard
- **Large Icons**: `w-5 h-5` to `w-6 h-6` for emphasis
- **Icon Spacing**: `mr-2` for compact, `mr-3` for standard layouts
- **Icon Colors**: Use `text-primary-500` for interactive elements, `text-gray-500` for informational

### 🎨 Animation & Effects
- **Fade In**: Use `animate-fade-in` for smooth content loading
- **Slide Up**: Use `animate-slide-up` for modal/card entrances
- **Soft Shadows**: Use `shadow-soft` for subtle depth
- **Medical Shadows**: Use `shadow-medical` for healthcare-themed elements

### 🌙 Dark Mode Considerations
- All components automatically adapt using `dark:` prefixes
- Primary colors remain consistent in dark mode
- Use safelist classes defined in tailwind.config.js for proper dark mode support

---

## 🎨 Brand Application Examples

### Billing/Pricing Pages
- Primary Blue (`bg-primary-500`) for primary upgrade buttons and featured plan borders
- Medical Teal (`text-medical-500`) for feature checkmarks and success indicators
- Primary Blue hover (`hover:bg-primary-600`) for button hover states
- Compact spacing with `py-6` page padding and `gap-6` card spacing

### Healthcare Dashboard Components
- Use `shadow-medical` for healthcare-specific cards
- Apply `bg-linear-to-r from-gradient-start to-gradient-end` for hero sections
- Use Inter font family for clean, medical-appropriate typography
- Leverage `animate-fade-in` and `animate-slide-up` for smooth user interactions

### Form Elements
- Primary focus states: `focus:ring-primary-500 focus:border-primary-500`
- Success states: `border-medical-500 text-medical-600`
- Error states: Use standard red colors
- Disabled states: `bg-gray-100 text-gray-400`