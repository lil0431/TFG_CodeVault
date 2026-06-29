# 🎨 Documentación de Header y Footer - WeaponsBara

## 📋 Resumen de Cambios

Se ha implementado un diseño completo y moderno para los headers y footers de la aplicación, siguiendo el tema dark/militar de WeaponsBara con colores rojo oscuro y negro.

---

## 🎯 Archivos Modificados

### **1. CSS (`style.css`)**
- ✅ Variables CSS globales para colores del tema
- ✅ Estilos completos para el header (fixed top)
- ✅ Estilos completos para el footer
- ✅ Diseño responsive para móviles y tablets
- ✅ Animaciones y efectos hover

### **2. Headers**
- ✅ `header.html` - Header principal con top bar
- ✅ `header.html` - Header alternativo simplificado

### **3. Footers**
- ✅ `footer.html` - Footer con scripts de JavaScript
- ✅ `footer2.html` - Footer simplificado

---

## 🎨 Características del Header

### **Top Bar (Barra Superior)**
- 📞 Información de contacto (teléfono, email, horario)
- 🌐 Enlaces a redes sociales (5 plataformas)
- 🎨 Fondo oscuro translúcido con borde inferior rojo

### **Navegación Principal**
- 🔰 Logo animado con icono circular
- 📱 Menú responsive (hamburguesa en móvil)
- 🔗 5 enlaces principales:
  - Inicio
  - Capibaras
  - Productos
  - Tiendas
  - Mi Cuenta (con botón destacado)
- ✨ Efectos hover con brillo rojo
- 📌 Header fijo (fixed position)

### **Diseño Responsive**
- 💻 **Desktop (>968px)**: Top bar visible, menú horizontal
- 📱 **Tablet/Mobile (<968px)**: 
  - Top bar oculto
  - Menú hamburguesa
  - Menú desplegable vertical
  - Logo reducido

---

## 🎨 Características del Footer

### **Estructura (4 Columnas)**

#### **1. WeaponsBara**
- Descripción de la empresa
- 5 iconos de redes sociales con efectos hover

#### **2. Navegación**
- Enlaces principales del sitio
- Acceso rápido a secciones

#### **3. Acceso**
- Portal de empleados
- Mi cuenta
- Usuarios
- Documentación técnica
- Certificaciones
- Políticas de seguridad

#### **4. Contacto Oficial**
- 📍 Dirección: Pentagon, Washington DC
- 📞 Teléfono: +1 (555) 123-4567
- 📧 Email: contacto@weaponsbara.gov
- 📠 Fax: +1 (555) 123-4568
- 🕐 Horario: Lun-Vie: 8:00-18:00 EST

### **Footer Bottom**
- Copyright 2025
- Clasificación: CONFIDENCIAL
- Gobierno de Estados Unidos

---

## 🎨 Paleta de Colores

```css
--primary-dark: #0a0a0a;      /* Negro principal */
--secondary-dark: #1a1a1a;    /* Negro secundario */
--dark-grey: #2a2a2a;         /* Gris oscuro */
--blood-red: #8b0000;         /* Rojo sangre */
--crimson: #dc143c;           /* Carmesí */
--burgundy: #6b0f1a;          /* Borgoña */
--text-light: #e0e0e0;        /* Texto claro */
--text-grey: #a0a0a0;         /* Texto gris */
--accent-red: #b91c1c;        /* Rojo acento */
```

---

## 🔧 JavaScript Incluido

### **Funcionalidad del Menú Móvil**

```javascript
// Toggle del menú móvil
function toggleMobileMenu() {
    navMenu.classList.toggle('active');
}

// Cerrar menú al hacer click fuera
// Cerrar menú al redimensionar a desktop
```

### **Características:**
- ✅ Apertura/cierre suave del menú
- ✅ Cierre automático al hacer click fuera
- ✅ Cierre automático al redimensionar ventana
- ✅ Compatible con todos los navegadores modernos

---

## 📱 Breakpoints Responsive

### **Desktop (>968px)**
- Top bar visible con toda la información
- Menú horizontal con 5 elementos
- Espaciado completo
- Header de 120px de alto

### **Tablet (768px - 968px)**
- Top bar oculto
- Menú hamburguesa activado
- Logo a tamaño completo
- Header de 80px de alto

### **Mobile (<480px)**
- Logo reducido (1.3rem)
- Icono de logo más pequeño (40px)
- Top bar info en columna
- Footer en una columna

---

## ✨ Efectos y Animaciones

### **Header**
- 🎯 Logo rota 360° al hacer hover
- ✨ Enlaces con borde inferior animado
- 💫 Text-shadow con efecto de brillo rojo
- 🔄 Transiciones suaves (0.3s)
- 📦 Box-shadow con efecto de profundidad

### **Footer**
- 🔗 Enlaces cambian a color carmesí al hover
- 🌟 Iconos sociales escalan y brillan
- 📈 Cards elevan con hover
- 🎨 Gradientes en secciones

---

## 🚀 Cómo Usar

### **En tus templates Mustache:**

```html
<!-- Incluir header -->
{{> header}}

<!-- Tu contenido aquí -->
<div class="container">
    <h1>Contenido de tu página</h1>
</div>

<!-- Incluir footer -->
{{> footer}}
```

### **Alternativa simplificada:**

```html
{{> header}}
<!-- Contenido -->
{{> footer2}}
```

---

## 🔗 Enlaces Importantes

### **Redes Sociales (Actualizar URLs):**
- Facebook: `https://www.facebook.com/username`
- Twitter: `https://www.twitter.com/username`
- LinkedIn: `https://www.linkedin.com/company/username`
- Instagram: `https://www.instagram.com/username`
- YouTube: `https://www.youtube.com/user/username`

### **Rutas de la Aplicación:**
- `/` - Inicio
- `/capybaras` - Listado de capibaras
- `/products` - Productos
- `/shops` - Tiendas
- `/me` - Mi cuenta
- `/login` - Portal de empleados
- `/users` - Usuarios (admin)

---

## 🛠️ Personalización

### **Cambiar Colores:**
Editar las variables CSS en `style.css`:

```css
:root {
    --primary-dark: #TU_COLOR;
    --crimson: #TU_COLOR_ACENTO;
    /* ... más variables */
}
```

### **Cambiar Logo:**
Reemplazar `/images/logo.png` con tu logo (recomendado: 100x100px, formato PNG con transparencia)

### **Añadir/Quitar Enlaces:**
Editar las secciones `<ul class="nav-menu">` en los headers

---

## ✅ Compatibilidad

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ✅ Mobile iOS 14+
- ✅ Mobile Android 10+

---

## 📝 Notas Importantes

1. **Header Fijo**: El header tiene `position: fixed`, por lo que se incluye un `<div class="header-spacer"></div>` para evitar que el contenido quede detrás.

2. **Font Awesome**: Se usa la versión 6.5.1 desde CDN. Los iconos están disponibles globalmente.

3. **Responsive**: El diseño se adapta automáticamente a diferentes tamaños de pantalla.

4. **JavaScript**: El script del menú móvil está en los footers y es necesario para la funcionalidad móvil.

---

## 🎯 Próximos Pasos Sugeridos

- [ ] Actualizar URLs de redes sociales reales
- [ ] Añadir página de "Sobre Nosotros"
- [ ] Implementar búsqueda en el header
- [ ] Añadir dropdown menus para categorías
- [ ] Implementar breadcrumbs
- [ ] Añadir indicador de página activa en navegación

---

## 📞 Soporte

Para dudas o modificaciones adicionales, contactar al equipo de desarrollo.

**Versión**: 1.0  
**Última actualización**: 27 de octubre de 2025  
**Desarrollado para**: WeaponsBara Application
