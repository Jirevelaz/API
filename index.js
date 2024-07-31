require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();

app.use(bodyParser.json());
app.use(cors());
app.use(cookieParser());

//puerto cluster 
const uri = 'mongodb+srv://jirevelazco4:1234@cluster0.rj3du1r.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const clientOptions = { serverApi: { version: '1', strict: true, deprecationErrors: true } };
async function run() {
  try {
    // Create a Mongoose client with a MongoClientOptions object to set the Stable API version
    await mongoose.connect(uri, clientOptions);
    await mongoose.connection.db.admin().command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } catch (error) {
    console.log(error);
  }
}

run();

// Import routes
const asignacionController = require('./routes/asignacion-routes');
const cat_equipoController = require('./routes/cat_equipo-routes-api');
const cat_rolesControllers = require('./routes/cat_roles-routes');
const reportesControllers = require('./routes/reportes-routes');
const t_personaController = require('./routes/t_personas-routes');
const usercontroller = require('./routes/user-routes-api');

//use routes
app.use('/asignacion', asignacionController);
app.use('/cat_equipo', cat_equipoController );
app.use('/cat_roles', cat_rolesControllers);
app.use('/reportes', reportesControllers);
app.use('/persona', t_personaController);
app.use('/user', usercontroller);


//debe ser el puerto por defecto el (4000) y va entre comillas paradas (`)
app.listen(4000, () => {
    console.log(`Server running at http://localhost:${4000}`);
  });