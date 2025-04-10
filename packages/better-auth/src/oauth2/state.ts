import { APIError } from "better-call";
import { z } from "zod";
import { generateRandomString, symmetricDecrypt, symmetricEncrypt } from "../crypto";
import type { GenericEndpointContext } from "../types";

export async function generateState(c: GenericEndpointContext, link?: { email: string; userId: string; }) {
  const callbackURL = c.body?.callbackURL || c.context.options.baseURL;
  if (!callbackURL) {
    throw new APIError("BAD_REQUEST", { message: "callbackURL is required" });
  }
  
  const codeVerifier = generateRandomString(128);
  const stateData = {
    callbackURL,
    codeVerifier,
    errorURL: c.body?.errorCallbackURL,
    newUserURL: c.body?.newUserCallbackURL,
    link,
    expiresAt: Date.now() + 10 * 60 * 1000,
    requestSignUp: c.body?.requestSignUp
  };
  
  const encryptedState = await symmetricEncrypt({
    key: c.context.secret,
    data: JSON.stringify(stateData)
  });
  
  return {
    state: encodeURIComponent(encryptedState),
    codeVerifier
  };
}

// Modified parseState function
export async function parseState(c: GenericEndpointContext) {
  const encryptedState = decodeURIComponent(c.query.state || c.body.state);
  try {
    const decryptedState = await symmetricDecrypt({
      key: c.context.secret,
      data: encryptedState
    });
    
    const parsedData = z.object({
      callbackURL: z.string(),
      codeVerifier: z.string(),
      errorURL: z.string().optional(),
      newUserURL: z.string().optional(),
      expiresAt: z.number(),
      link: z.object({
        email: z.string(),
        userId: z.string()
      }).optional(),
      requestSignUp: z.boolean().optional()
    }).parse(JSON.parse(decryptedState));
    
    if (!parsedData.errorURL) {
      parsedData.errorURL = `${c.context.baseURL}/error`;
    }

    if (parsedData.expiresAt < Date.now()) {
      throw new Error("State expired");
    }
    
    return parsedData;
  } catch (error) {
    c.context.logger.error("Failed to parse state", error);
    throw c.redirect(`${c.context.baseURL}/error?error=please_restart_the_process`);
  }
}