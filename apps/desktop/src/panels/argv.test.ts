import { describe, expect, it } from "vitest";
import { splitArgs } from "./argv";

describe("splitArgs", () => {
  it("splits on whitespace and honours quotes", () => {
    expect(splitArgs("status --porcelain")).toEqual(["status", "--porcelain"]);
    expect(splitArgs(`log --format="%h %s" -n 3`)).toEqual(["log", "--format=%h %s", "-n", "3"]);
    expect(splitArgs(`-c 'print(1)'`)).toEqual(["-c", "print(1)"]);
    expect(splitArgs(`a "" b`)).toEqual(["a", "", "b"]);
    expect(splitArgs("   ")).toEqual([]);
  });
  it("does not interpret shell metacharacters", () => {
    expect(splitArgs("status ; rm -rf / && echo $HOME")).toEqual(["status", ";", "rm", "-rf", "/", "&&", "echo", "$HOME"]);
  });
  it("rejects unterminated quotes", () => {
    expect(() => splitArgs(`"oops`)).toThrow();
  });
});
