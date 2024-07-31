const mongoose = require('mongoose');

// Definición del esquema de Reportes
const reportesSchema = new mongoose.Schema({
    id_reporte: { type: Number, required: true },
    id_usuario: { type: Number, required: true },
    id_equipo: { type: Number, required: true },
    id_usuario_tecnico: { type: Number, default: null },
    descripcion_problema: { type: String, required: true },
    solucion_problema: { type: String, default: null },
    estatus: { type: Number, default: 1 },
    fecha: { type: Date, default: Date.now }
});

// Método para mostrar datos
reportesSchema.methods.showData = function() {
    return {
        id_reporte: this.id_reporte,
        id_usuario: this.id_usuario,
        id_equipo: this.id_equipo,
        id_usuario_tecnico: this.id_usuario_tecnico,
        descripcion_problema: this.descripcion_problema,
        solucion_problema: this.solucion_problema,
        estatus: this.estatus,
        fecha: this.fecha
    };
};

// Creación del modelo Reportes
const Reportes = mongoose.model('Reportes', reportesSchema);

module.exports = Reportes;
