const mongoose = require('mongoose');

// Definición del esquema de CatRoles
const catRolesSchema = new mongoose.Schema({
    id_rol: { type: Number, required: true },
    nombre: { type: String, required: true },
    descripcion: { type: String, default: null }
});

// Método para mostrar datos
catRolesSchema.methods.showData = function() {
    return {
        id_rol: this.id_rol,
        nombre: this.nombre,
        descripcion: this.descripcion
    };
};

// Creación del modelo CatRoles
const CatRoles = mongoose.model('CatRoles', catRolesSchema);

module.exports = CatRoles;
