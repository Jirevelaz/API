const mongoose = require('mongoose');

// Definición del esquema de CatEquipo
const catEquipoSchema = new mongoose.Schema({
    id_equipo: { type: Number, required: true },
    nombre: { type: String, required: true },
    descripcion: { type: String, default: null }
});

// Método para mostrar datos
catEquipoSchema.methods.showData = function() {
    return {
        id_equipo: this.id_equipo,
        nombre: this.nombre,
        descripcion: this.descripcion
    };
};

// Creación del modelo CatEquipo
const CatEquipo = mongoose.model('CatEquipo', catEquipoSchema);

module.exports = CatEquipo;
