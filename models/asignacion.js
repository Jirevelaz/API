const mongoose = require('mongoose');

// Definición del esquema de Asignacion
const asignacionSchema = new mongoose.Schema({
    id_asignacion: { type: Number, required: true },
    id_persona: { type: Number, required: true },
    id_equipo: { type: Number, required: true },
    marca: { type: String, default: null },
    modelo: { type: String, default: null },
    color: { type: String, default: null },
    descripcion: { type: String, default: null },
    memoria: { type: String, default: null },
    disco_duro: { type: String, default: null },
    procesador: { type: String, default: null }
});

// Método para mostrar datos
asignacionSchema.methods.showData = function() {
    return {
        id_asignacion: this.id_asignacion,
        id_persona: this.id_persona,
        id_equipo: this.id_equipo,
        marca: this.marca,
        modelo: this.modelo,
        color: this.color,
        descripcion: this.descripcion,
        memoria: this.memoria,
        disco_duro: this.disco_duro,
        procesador: this.procesador
    };
};

// Creación del modelo Asignacion
const Asignacion = mongoose.model('Asignacion', asignacionSchema);

module.exports = Asignacion;
