/** Base class for domain-level validation failures. */
export class DomainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class InvalidMacAddressError extends DomainError {}
export class InvalidIpAddressError extends DomainError {}
export class InvalidCidrError extends DomainError {}
