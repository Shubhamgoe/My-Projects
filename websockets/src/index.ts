import WebSocket,{ WebSocketServer} from "ws";
import http from 'http';

const server = http.createServer(function(request:any, response:any){
    console.log((new Date())+' Recieved request for ')
});