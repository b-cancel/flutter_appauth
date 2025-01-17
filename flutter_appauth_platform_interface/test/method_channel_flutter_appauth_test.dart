import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

// ignore: avoid_relative_lib_imports
import '../lib/flutter_appauth_platform_interface.dart';
// ignore: avoid_relative_lib_imports
import '../lib/src/method_channel_flutter_appauth.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const MethodChannel channel = MethodChannel(
    'crossingthestreams.io/flutter_appauth',
  );
  final List<MethodCall> log = <MethodCall>[];
  channel.setMockMethodCallHandler(
    (MethodCall methodCall) async {
      log.add(methodCall);
    },
  );

  tearDown(() {
    log.clear();
  });

  final MethodChannelFlutterAppAuth flutterAppAuth =
      MethodChannelFlutterAppAuth();

  test(
    'authorize',
    () async {
      await flutterAppAuth.authorize(
        AuthorizationRequest(
          'someClientId',
          'someRedirectUrl',
          discoveryUrl: 'someDiscoveryUrl',
          loginHint: 'someLoginHint',

          ///
          /// NEW VAR(s)
          ///
          state: 'abcdefg',
        ),
      );
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'authorize',
            arguments: <String, Object?>{
              'clientId': 'someClientId',
              'issuer': null,
              'redirectUrl': 'someRedirectUrl',
              'discoveryUrl': 'someDiscoveryUrl',
              'loginHint': 'someLoginHint',

              ///
              /// NEW VAR(s)
              ///
              'state': 'abcdefg',
              'scopes': null,
              'serviceConfiguration': null,
              'additionalParameters': null,
              'allowInsecureConnections': false,
              'preferEphemeralSession': false,
              'promptValues': null,
              'responseMode': null,
              'nonce': null,
            },
          ),
        ],
      );
    },
  );

  test(
    'authorizeAndExchangeCode',
    () async {
      await flutterAppAuth.authorizeAndExchangeCode(
        AuthorizationTokenRequest(
          'someClientId',
          'someRedirectUrl',
          discoveryUrl: 'someDiscoveryUrl',
          loginHint: 'someLoginHint',
          responseMode: 'fragment',

          ///
          /// NEW VAR(s)
          ///
          state: 'abcdefg',
        ),
      );
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'authorizeAndExchangeCode',
            arguments: <String, Object?>{
              'clientId': 'someClientId',
              'issuer': null,
              'redirectUrl': 'someRedirectUrl',
              'discoveryUrl': 'someDiscoveryUrl',
              'loginHint': 'someLoginHint',

              ///
              /// NEW VAR(s)
              ///
              'state': 'abcdefg',
              'scopes': null,
              'serviceConfiguration': null,
              'additionalParameters': null,
              'allowInsecureConnections': false,
              'preferEphemeralSession': false,
              'promptValues': null,
              'clientSecret': null,
              'refreshToken': null,
              'authorizationCode': null,
              'grantType': 'authorization_code',
              'codeVerifier': null,
              'responseMode': 'fragment',
              'nonce': null,
            },
          ),
        ],
      );
    },
  );

  group(
    'token',
    () {
      test(
        'cannot infer grant type',
        () async {
          expect(
            () async => await flutterAppAuth.token(
              TokenRequest(
                'someClientId',
                'someRedirectUrl',
                discoveryUrl: 'someDiscoveryUrl',
              ),
            ),
            throwsArgumentError,
          );
        },
      );
      test(
        'infers refresh token grant type',
        () async {
          await flutterAppAuth.token(
            TokenRequest(
              'someClientId',
              'someRedirectUrl',
              discoveryUrl: 'someDiscoveryUrl',
              refreshToken: 'someRefreshToken',
            ),
          );
          expect(
            log,
            <Matcher>[
              isMethodCall(
                'token',
                arguments: <String, Object?>{
                  'clientId': 'someClientId',
                  'issuer': null,
                  'redirectUrl': 'someRedirectUrl',
                  'discoveryUrl': 'someDiscoveryUrl',
                  'scopes': null,
                  'serviceConfiguration': null,
                  'additionalParameters': null,
                  'allowInsecureConnections': false,
                  'clientSecret': null,
                  'refreshToken': 'someRefreshToken',
                  'authorizationCode': null,
                  'grantType': 'refresh_token',
                  'codeVerifier': null,
                  'nonce': null,
                },
              ),
            ],
          );
        },
      );

      test(
        'infers authorization code grant type',
        () async {
          await flutterAppAuth.token(
            TokenRequest(
              'someClientId',
              'someRedirectUrl',
              discoveryUrl: 'someDiscoveryUrl',
              authorizationCode: 'someAuthorizationCode',
            ),
          );
          expect(
            log,
            <Matcher>[
              isMethodCall(
                'token',
                arguments: <String, Object?>{
                  'clientId': 'someClientId',
                  'issuer': null,
                  'redirectUrl': 'someRedirectUrl',
                  'discoveryUrl': 'someDiscoveryUrl',
                  'scopes': null,
                  'serviceConfiguration': null,
                  'additionalParameters': null,
                  'allowInsecureConnections': false,
                  'clientSecret': null,
                  'refreshToken': null,
                  'authorizationCode': 'someAuthorizationCode',
                  'grantType': 'authorization_code',
                  'codeVerifier': null,
                  'nonce': null,
                },
              ),
            ],
          );
        },
      );

      test(
        'sends specified grant type',
        () async {
          await flutterAppAuth.token(
            TokenRequest(
              'someClientId',
              'someRedirectUrl',
              discoveryUrl: 'someDiscoveryUrl',
              grantType: 'someGrantType',
            ),
          );
          expect(
            log,
            <Matcher>[
              isMethodCall(
                'token',
                arguments: <String, Object?>{
                  'clientId': 'someClientId',
                  'issuer': null,
                  'redirectUrl': 'someRedirectUrl',
                  'discoveryUrl': 'someDiscoveryUrl',
                  'scopes': null,
                  'serviceConfiguration': null,
                  'additionalParameters': null,
                  'allowInsecureConnections': false,
                  'clientSecret': null,
                  'refreshToken': null,
                  'authorizationCode': null,
                  'grantType': 'someGrantType',
                  'codeVerifier': null,
                  'nonce': null,
                },
              ),
            ],
          );
        },
      );
    },
  );

  test(
    'endSession',
    () async {
      await flutterAppAuth.endSession(
        EndSessionRequest(
          idTokenHint: 'someIdToken',
          postLogoutRedirectUrl: 'somePostLogoutRedirectUrl',
          state: 'someState',
          discoveryUrl: 'someDiscoveryUrl',
        ),
      );
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'endSession',
            arguments: <String, Object?>{
              'idTokenHint': 'someIdToken',
              'postLogoutRedirectUrl': 'somePostLogoutRedirectUrl',
              'state': 'someState',
              'allowInsecureConnections': false,
              'additionalParameters': null,
              'issuer': null,
              'discoveryUrl': 'someDiscoveryUrl',
              'serviceConfiguration': null,
              'preferEphemeralSession': false,
            },
          ),
        ],
      );
    },
  );
}
