/* tslint:disable */
/* eslint-disable */
/**
* @param {number} k
* @param {number} a
* @param {number} b
* @returns {Uint8Array}
*/
export function create_simple_add_proof_wasm(k: number, a: number, b: number): Uint8Array;
/**
* @param {number} k
* @param {number} a
* @param {number} b
* @param {Uint8Array} proof
* @returns {boolean}
*/
export function verify_simple_add_proof_wasm(k: number, a: number, b: number, proof: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly create_simple_add_proof_wasm: (a: number, b: number, c: number, d: number) => void;
  readonly verify_simple_add_proof_wasm: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
