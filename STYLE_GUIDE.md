# 🎨 UI Style Guide

This document defines the core color palette and usage guidelines for your UI.

---

## 🌈 Color Palette

| Color Name   | Hex       | Usage Recommendation                         |
|--------------|-----------|----------------------------------------------|
| Ocean Blue   | `#05668D` | Primary buttons, headers, brand accent       |
| Deep Teal    | `#028090` | Hover states, icons, secondary buttons       |
| Mint Green   | `#00A896` | Success states, highlights, call-to-actions  |
| Aqua Green   | `#02C39A` | Accents, tags, links                         |

---

## 🧱 Usage Guidelines

### 🎯 Primary Color – Ocean Blue `#05668D`
- Use for navigation bars, primary action buttons, or branding highlights.
- Avoid overusing to preserve impact.

### 🧭 Secondary Color – Deep Teal `#028090`
- Ideal for button hovers, link hovers, or secondary UI elements.
- Pairs well with Ocean Blue for subtle contrast.

### ✅ Accent Color – Mint Green `#00A896`
- Great for success messages, form indicators, or badges.

### 🔗 Supporting Accent – Aqua Green `#02C39A`
- Use for hyperlinks, borders, tags, or minor CTAs.

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
- **Primary Buttons**: Ocean Blue background with Deep Teal hover
- **Secondary Buttons**: Gray background with darker gray hover
- **Button Padding**: `py-2 px-4` for compact, `py-3 px-4` for standard
- **Button Text**: `text-sm font-medium` for compact, `text-base font-medium` for standard

### 📱 Responsive Grid Patterns
- **Pricing Cards**: `grid-cols-1 md:grid-cols-3` for 3-tier layouts
- **Info Sections**: `grid-cols-1 lg:grid-cols-2` for side-by-side content
- **Feature Lists**: Use `space-y-2` for compact lists, `space-y-3` for standard

### ✨ Special Component Patterns

#### 💳 Pricing Card Best Practices
- Use `scale-105` for featured/popular plans
- Include "Most Popular" badge with `bg-ocean text-white` styling
- Use Mint Green checkmarks (`text-mint`) for included features
- Use gray X marks (`text-gray-400`) for excluded features
- Keep feature lists to 5-6 items maximum for readability

#### 🏷️ Status Indicators
- **Active/Success**: Use Mint Green (`#00A896`)
- **Warning/Pending**: Use appropriate warning colors
- **Inactive/Disabled**: Use `text-gray-400` or `bg-gray-100`

### 🖼️ Icon Guidelines
- **Standard Icons**: `w-4 h-4` for compact layouts, `w-5 h-5` for standard
- **Large Icons**: `w-5 h-5` to `w-6 h-6` for emphasis
- **Icon Spacing**: `mr-2` for compact, `mr-3` for standard layouts
- **Icon Colors**: Use brand colors for interactive elements, gray for informational

---

## 🎨 Brand Application Examples

### Billing/Pricing Pages
- Ocean Blue for primary upgrade buttons and featured plan borders
- Mint Green for feature checkmarks and success indicators
- Deep Teal for button hover states
- Compact spacing with `py-6` page padding and `gap-6` card spacing