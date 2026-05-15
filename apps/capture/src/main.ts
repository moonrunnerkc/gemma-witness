import "./styles/global.css";
import App from "./app.svelte";
import { mount } from "svelte";

const root = document.getElementById("app");
if (root === null) {
  throw new Error("missing #app root element; check apps/capture/index.html");
}

mount(App, { target: root });
