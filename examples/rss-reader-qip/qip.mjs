// A host for QIP Content components: https://qip.dev/docs/content-component
//
// A component is a WebAssembly module with no imports. The host writes the
// input into its memory, sets numeric uniforms, calls render, and copies
// out the returned range. The component can't reach the network, the disk
// or the clock: everything it knows arrives in its input or a uniform.

import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const utf8 = new TextDecoder("utf-8", { fatal: true });

// Rejection is a component's recoverable "this input is invalid". The
// instance stays usable.
export class Rejection extends Error {
  constructor(component, offset, mode) {
    const where = offset === undefined ? "" : ` at input byte ${offset}`;
    super(`${component} rejected its input${where}${mode ? `: ${mode}` : ""}`);
    this.offset = offset;
    this.mode = mode;
  }
}

// load compiles a component. modes names its failure modes, in order, for
// error messages.
export async function load(path, { name = path, modes = [] } = {}) {
  const module = await WebAssembly.compile(await readFile(path));
  if (WebAssembly.Module.imports(module).length > 0) {
    throw new Error(`${name}: a Content component must have no imports`);
  }
  return new Component(name, module, modes);
}

export class Component {
  #module;
  #instance = null;

  constructor(name, module, modes) {
    this.name = name;
    this.#module = module;
    this.modes = modes;
  }

  // An instance is reused across renders, and replaced after a trap,
  // when its memory may be inconsistent.
  get #exports() {
    this.#instance ??= new WebAssembly.Instance(this.#module, {});
    return this.#instance.exports;
  }

  get inputCap() {
    const x = this.#exports;
    return x.input_utf8_cap?.() ?? x.input_bytes_cap();
  }

  #contentType(side) {
    const x = this.#exports;
    const ptr = x[`${side}_content_type_ptr`];
    if (!ptr) return null;
    const bytes = new Uint8Array(x.memory.buffer, ptr() >>> 0, x[`${side}_content_type_size`]());
    return { bytes, type: utf8.decode(bytes) };
  }

  // render runs the component once. input is a string or bytes; uniforms
  // maps names to numbers or bigints. It returns the output bytes and the
  // output's content type, with a fresh multipart boundary if it has one.
  render(input, uniforms = {}) {
    const x = this.#exports;
    const bytes = typeof input === "string" ? Buffer.from(input) : input;
    if (x.input_utf8_cap && typeof input !== "string") {
      utf8.decode(bytes); // throws unless it's valid UTF-8, as the component requires
    }
    if (bytes.length > this.inputCap) {
      throw new Error(`${this.name}: ${bytes.length} bytes is more than its ${this.inputCap}-byte input`);
    }
    new Uint8Array(x.memory.buffer, x.input_ptr() >>> 0, bytes.length).set(bytes);

    for (const key of Object.keys(uniforms).sort()) {
      const setter = Object.keys(x).find((n) => n === `uniform_set_${key}` || n.startsWith(`uniform_set_${key}__`));
      if (!setter) throw new Error(`${this.name} has no uniform ${key}`);
      setUniform(x[setter], uniforms[key]);
    }

    // A multipart producer reads its boundary's UUID from memory on each
    // call, so the host can choose one that can't appear in the input.
    const out = this.#contentType("output");
    let contentType = out?.type ?? null;
    if (contentType?.includes(";boundary=uuid-")) {
      const uuid = Buffer.from(randomUUID());
      out.bytes.set(uuid, out.bytes.length - uuid.length);
      contentType = out.type.slice(0, -uuid.length) + uuid.toString();
    }

    let result;
    try {
      result = BigInt.asUintN(64, x.render(bytes.length));
    } catch (err) {
      this.#instance = null;
      throw new Error(`${this.name} trapped: ${err.message}`);
    }
    if (result >> 63n) {
      const detail = Number(result & 0xffffffffn);
      const n = x.failure_modes_per_input_offset?.() ?? 0;
      if (n === 0) throw new Rejection(this.name);
      throw new Rejection(this.name, Math.floor(detail / n), this.modes[detail % n] ?? `mode ${detail % n}`);
    }
    const ptr = Number((result >> 32n) & 0x7fffffffn);
    const size = Number(result & 0xffffffffn);
    const cap = x.output_utf8_cap?.() ?? x.output_bytes_cap();
    if (size > cap || ptr + size > x.memory.buffer.byteLength) {
      this.#instance = null;
      throw new Error(`${this.name} returned an output range outside its memory`);
    }
    return { body: Buffer.from(x.memory.buffer.slice(ptr, ptr + size)), contentType };
  }
}

// setUniform calls a setter whose parameter may be i32, i64, f32 or f64.
// JavaScript can't see the type, but passing a number to an i64, or a
// bigint to anything else, throws a TypeError, so it tries both.
function setUniform(setter, value) {
  try {
    setter(typeof value === "bigint" ? value : BigInt(value));
  } catch (err) {
    if (!(err instanceof TypeError)) throw err;
    setter(Number(value));
  }
}
