import fetch from "isomorphic-unfetch";
import { v4 as uuidv4 } from "uuid";
import log from "loglevel";

export interface IPrincipal {
  id: string;
  policyVersion?: unknown;
  scope?: string;
  roles: string[];
  attr?: {
    [key: string]: unknown;
  };
}

export interface IAuxData {
  jwt?: IJwt;
}

export interface IJwt {
  token: string;
  keySetId?: string;
}

export interface IAuthorize {
  actions: string[];
  resource: {
    policyVersion?: unknown;
    kind: string;
    scope?: string;
    instances: {
      [resourceKey: string]: {
        attr?: {
          [key: string]: unknown;
        };
      };
    };
  };
  principal: IPrincipal;
  auxData?: IAuxData;
}

export enum ValidationErrorSource {
  SOURCE_RESOURCE = "SOURCE_RESOURCE",
  SOURCE_PRINCIPAL = "SOURCE_PRINCIPAL",
}

export interface ValidationError {
  path: string;
  message: string;
  source: ValidationErrorSource;
}

export interface IAuthorizeResponse {
  requestID: string;
  resourceInstances: {
    [resourceKey: string]: {
      actions: {
        [key: string]: AuthorizeEffect;
      };
      validationErrors?: ValidationError[];
    };
  };
}

export enum AuthorizeEffect {
  ALLOW = "EFFECT_ALLOW",
  DENY = "EFFECT_DENY",
}

export class AuthorizationError extends Error { }

export interface ICerbosResponse {
  isAuthorized: (resourceKey: string, action: string) => boolean;
}

export class CerbosResponseWrapper implements ICerbosResponse {
  readonly resp: IAuthorizeResponse;

  constructor(resp: IAuthorizeResponse) {
    this.resp = resp;
  }

  isAuthorized(resourceKey: string, action: string): boolean {
    try {
      const allowed =
        this.resp.resourceInstances[resourceKey]?.actions[action] ==
        AuthorizeEffect.ALLOW;
      return allowed ?? false;
    } catch (e) {
      return false;
    }
  }
}

export interface CerbosOptions {
  hostname: string;
  logLevel?: log.LogLevelDesc;
  handleValidationErrors?: "error" | "log" | false;
  playgroundInstance?: string;
}

export interface IResourcesQueryPlanResponseConditionOperand {
  condition?: IResourcesQueryPlanResponseCondition;
  expression?: IResourcesQueryPlanResponseExpression;
}

export interface IResourcesQueryPlanResponseExpression {
  operator?: string;
  operands?: IResourcesQueryPlanResponseExpressionOperand[];
}

export interface IResourcesQueryPlanResponseExpressionOperand {
  value?: object;
  expression?: IResourcesQueryPlanResponseExpression;
  variable?: string;
}

export interface IResourcesQueryPlanRequest {
  requestId?: string;
  action: string;
  principal?: IPrincipal;
  resourceKind: string;
  policyVersion?: string;
  auxData?: IAuxData;
}

export interface IResourcesQueryPlanResponse {
  requestId?: string;
  action: string;
  resourceKind: string;
  policyVersion?: string;
  filter: IResourcesQueryPlanResponseConditionOperand;
  filterDebug?: string;
}

export interface IResourcesQueryPlanResponseCondition {
  operator?: string;
  nodes?: IResourcesQueryPlanResponseConditionOperand[];
}

export class Cerbos {
  private host: string;
  private log: log.Logger;
  private playgroundInstance?: string;
  private handleValidationErrors?: "error" | "log" | false;

  constructor({
    hostname,
    logLevel,
    playgroundInstance,
    handleValidationErrors,
  }: CerbosOptions) {
    this.host = hostname;
    this.playgroundInstance = playgroundInstance;
    this.handleValidationErrors = handleValidationErrors;
    this.log = log.noConflict();
    this.log.setLevel(logLevel ?? "silent");
  }

  async resourcesQueryPlan(payload: IResourcesQueryPlanRequest): Promise<IResourcesQueryPlanResponse> {
    const url = `${this.host}/api/resources_query_plan`;
    if (!payload.requestId) {
      payload.requestId = uuidv4();
    }

    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    const response = await fetch(url, {
      method: "post",
      body: JSON.stringify(payload),
      headers
    });

    const data = await response.json();
    this.log.info("Cerbos.resourcesQueryPlan: Response", data);

    return data;
  }

  async check(data: IAuthorize): Promise<ICerbosResponse> {
    this.log.info("Cerbos.check", data);
    const payload = {
      requestId: uuidv4(),
      ...data,
      resource: {
        policyVersion: data.resource.policyVersion || "default",
        ...data.resource,
      },
      principal: {
        policyVersion: data.principal.policyVersion || "default",
        ...data.principal,
      },
    };
    this.log.debug("Cerbos.check Payload", payload);

    let headers: HeadersInit = {
      "Content-Type": "application/json",
    };

    if (this.playgroundInstance) {
      headers = {
        ...headers,
        "Playground-Instance": this.playgroundInstance,
      };
    }

    let resp: IAuthorizeResponse;

    // Fetch Data
    try {
      const response = await fetch(`${this.host}/api/check`, {
        method: "post",
        body: JSON.stringify(payload),
        headers,
      });
      resp = await response.json();
      this.log.info("Cerbos.check: Response", resp);
    } catch (e) {
      this.log.error("Cerbos.check Error", e);
      throw new AuthorizationError(
        `Could not connect to Cerbos PDP at ${this.host}`
      );
    }

    // Handle Validation Errors
    if (this.handleValidationErrors) {
      const validationErrors = resp.resourceInstances
        ? Object.values(resp.resourceInstances)
          .map((resource) => resource.validationErrors)
          .flat()
        : [];

      if (validationErrors.length > 0) {
        if (this.handleValidationErrors === "error") {
          throw new AuthorizationError(
            `Validation Error: ${JSON.stringify(validationErrors)}`
          );
        } else {
          this.log.error("Cerbos.check: Validation Errors", validationErrors);
        }
      }
    }

    return new CerbosResponseWrapper(resp);
  }
}
