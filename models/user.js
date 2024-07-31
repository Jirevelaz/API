const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Definición del esquema de Usuarios :V

const usuariosSchema = new mongoose.Schema({
    
    usuario: { type: String, required: true },
    password: { type: String, required: true },
    ubicacion: { type: String, default: null },
    activo: { type: Number, default: 1 },
    fecha_insert: { type: String, default: null },
    email: {
        type: String,
        required: true,
        unique: true
    },
    image: {
        type: String, // o puedes usar Buffer si prefieres almacenar la imagen directamente en la base de datos
        required: false
    }
});

// Método para comparar la contraseña ingresada con la hasheada

usuariosSchema.methods.comparePassword = function(password) {
    return bcrypt.compare(password, this.password);
};


// Creación del modelo Usuarios

const Usuarios = mongoose.model('User', usuariosSchema);

module.exports = Usuarios;
