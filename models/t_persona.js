const mongoose = require('mongoose');

// Definición del esquema de Persona
const personaSchema = new mongoose.Schema({
    id_persona: { type: Number, required: true },
    paterno: { type: String, required: true },
    materno: { type: String, default: null },
    nombre: { type: String, required: true },
    fecha_nacimiento: { type: String, required: true },
    sexo: { type: String, default: null },
    telefono: { type: String, default: null },
    correo: { type: String, default: null },
    fechaInsert: { type: Date, default: Date.now }
});

// Método para mostrar datos
personaSchema.methods.showData = function() {
    return {
        id_persona: this.id_persona,
        paterno: this.paterno,
        materno: this.materno,
        nombre: this.nombre,
        fecha_nacimiento: this.fecha_nacimiento,
        sexo: this.sexo,
        telefono: this.telefono,
        correo: this.correo,
        fechaInsert: this.fechaInsert
    };
};

// Creación del modelo Persona
const Persona = mongoose.model('Persona', personaSchema);

module.exports = Persona;
