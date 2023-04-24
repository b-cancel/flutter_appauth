#import "AppAuthIOSAuthorization.h"

@implementation AppAuthIOSAuthorization

- (id<OIDExternalUserAgentSession>) performAuthorization:(OIDServiceConfiguration *)serviceConfiguration clientId:(NSString*)clientId clientSecret:(NSString*)clientSecret scopes:(NSArray *)scopes redirectUrl:(NSString*)redirectUrl additionalParameters:(NSDictionary *)additionalParameters preferEphemeralSession:(BOOL)preferEphemeralSession result:(FlutterResult)result exchangeCode:(BOOL)exchangeCode nonce:(NSString*)nonce{
    /// additionalParameters of type NSDictionary* might contain overrides
    
    NSMutableDictionary *additional = [additionalParameters mutableCopy];
    NSString *theState = additional != nil ? additional[@"state"] : nil;
    if(theState != nil){
        [additional removeObjectForKey:@"state"];
    } else {
        theState = [OIDAuthorizationRequest generateState];
    }

    /// generate code verifier and challenge
    NSString *generatedCodeVerifier = [OIDAuthorizationRequest generateCodeVerifier];
    NSString *generatedCodeChallenge = [OIDAuthorizationRequest codeChallengeS256ForVerifier:generatedCodeVerifier];

    /// initWithConfiguration:
    /// clientId:
    /// clientSecret:
    /// scope:
    /// redirectURL:
    /// responseType:
    /// state:
    /// nonce: [OIDAuthorizationRequest generateState]
    /// codeVerifier:
    /// codeChallenge:
    /// codeChallengeMethod:
    /// additionalParameters:
    /// passedState != nil ? passedState : [OIDAuthorizationRequest generateState]

    /// [OIDScopeUtilities scopesWithArray:scopes]
    /// nonce != nil ? nonce : [OIDAuthorizationRequest generateState]
    /// scopes:@[OIDScopeOpenID,OIDScopeProfile]

    /// define the request
    OIDAuthorizationRequest *request = 
    [[OIDAuthorizationRequest alloc] initWithConfiguration:serviceConfiguration
                                        clientId:clientId
                                        clientSecret:clientSecret
                                        scope: nil
                                        // or is it scope?
                                        redirectURL:[NSURL URLWithString:redirectUrl]
                                        responseType: OIDResponseTypeCode
                                        state: theState
                                        nonce: nil
                                        codeVerifier: generatedCodeVerifier
                                        codeChallenge: generatedCodeChallenge
                                        codeChallengeMethod: OIDOAuthorizationRequestCodeChallengeMethodS256
                                        additionalParameters: additional];

    /// get the app delegate
    /// AppDelegate *appDelegate = [UIApplication sharedApplication].delegate;
                                    
    /// define the view that handles the request
    UIViewController *rootViewController = [UIApplication sharedApplication].delegate.window.rootViewController;

    /// the external user agent
    id<OIDExternalUserAgent> externalUserAgent = [self userAgentWithViewController:rootViewController useEphemeralSession:preferEphemeralSession];

    /*
    AppDelegate *appDelegate =
    (AppDelegate *)[UIApplication sharedApplication].delegate;
appDelegate.currentAuthorizationFlow =
    [OIDAuthState authStateByPresentingAuthorizationRequest:request
        presentingViewController:self
                        
    */

    /// extra step if we need to exachange code
    if(exchangeCode) {
        ///                                                                                                        callback:^(OIDAuthState *_Nullable authState ,NSError *_Nullable error)
        /// typedef void(^ OIDAuthStateAuthorizationCallback)                                                                (OIDAuthState *_Nullable authState, NSError *_Nullable error)
        return [OIDAuthState authStateByPresentingAuthorizationRequest:request presentingViewController:self callback:^(OIDAuthState *_Nullable authState, NSError *_Nullable error) {
            if(authState) {
                result([FlutterAppAuth processResponses:authState.lastTokenResponse authResponse:authState.lastAuthorizationResponse]);
            } else {
                [FlutterAppAuth finishWithError:AUTHORIZE_AND_EXCHANGE_CODE_ERROR_CODE message:[FlutterAppAuth formatMessageWithError:AUTHORIZE_ERROR_MESSAGE_FORMAT error:error] result:result];
            }
        }];
    } else {
        /// typedef void(^ OIDAuthorizationCallback)                                                                    (OIDAuthorizationResponse *_Nullable authorizationResponse, NSError *_Nullable error)
        return [OIDAuthorizationService presentAuthorizationRequest:request presentingViewController:self callback:^(OIDAuthorizationResponse *_Nullable authorizationResponse, NSError *_Nullable error) {
            if(authState) {
                NSMutableDictionary *processedResponse = [[NSMutableDictionary alloc] init];
                [processedResponse setObject:authorizationResponse.additionalParameters forKey:@"authorizationAdditionalParameters"];
                [processedResponse setObject:authorizationResponse.authorizationCode forKey:@"authorizationCode"];
                [processedResponse setObject:authorizationResponse.request.codeVerifier forKey:@"codeVerifier"];
                [processedResponse setObject:authorizationResponse.request.nonce forKey:@"nonce"];
                result(processedResponse);
            } else {
                [FlutterAppAuth finishWithError:AUTHORIZE_ERROR_CODE message:[FlutterAppAuth formatMessageWithError:AUTHORIZE_ERROR_MESSAGE_FORMAT error:error] result:result];
            }
        }];
  }
}

- (id<OIDExternalUserAgentSession>)performEndSessionRequest:(OIDServiceConfiguration *)serviceConfiguration requestParameters:(EndSessionRequestParameters *)requestParameters result:(FlutterResult)result {
  NSURL *postLogoutRedirectURL = requestParameters.postLogoutRedirectUrl ? [NSURL URLWithString:requestParameters.postLogoutRedirectUrl] : nil;
  
  OIDEndSessionRequest *endSessionRequest = requestParameters.state ? [[OIDEndSessionRequest alloc] initWithConfiguration:serviceConfiguration idTokenHint:requestParameters.idTokenHint postLogoutRedirectURL:postLogoutRedirectURL
                                                                                                                    state:requestParameters.state additionalParameters:requestParameters.additionalParameters] :[[OIDEndSessionRequest alloc] initWithConfiguration:serviceConfiguration idTokenHint:requestParameters.idTokenHint postLogoutRedirectURL:postLogoutRedirectURL
                                                                                                                                                                                                                                               additionalParameters:requestParameters.additionalParameters];

  UIViewController *rootViewController =
  [UIApplication sharedApplication].delegate.window.rootViewController;
  id<OIDExternalUserAgent> externalUserAgent = [self userAgentWithViewController:rootViewController useEphemeralSession:requestParameters.preferEphemeralSession];

  
  return [OIDAuthorizationService presentEndSessionRequest:endSessionRequest externalUserAgent:externalUserAgent callback:^(OIDEndSessionResponse * _Nullable endSessionResponse, NSError * _Nullable error) {
      if(!endSessionResponse) {
          NSString *message = [NSString stringWithFormat:END_SESSION_ERROR_MESSAGE_FORMAT, [error localizedDescription]];
          [FlutterAppAuth finishWithError:END_SESSION_ERROR_CODE message:message result:result];
          return;
      }
      NSMutableDictionary *processedResponse = [[NSMutableDictionary alloc] init];
      [processedResponse setObject:endSessionResponse.state forKey:@"state"];
      result(processedResponse);
  }];
}

- (id<OIDExternalUserAgent>)userAgentWithViewController:(UIViewController *)rootViewController useEphemeralSession:(BOOL)useEphemeralSession {
    if (useEphemeralSession) {
        return [[OIDExternalUserAgentIOSNoSSO alloc]
                initWithPresentingViewController:rootViewController];
    }
    return [[OIDExternalUserAgentIOS alloc]
            initWithPresentingViewController:rootViewController];
}

@end
