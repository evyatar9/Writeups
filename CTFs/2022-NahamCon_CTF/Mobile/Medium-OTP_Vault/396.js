var regeneratorRuntime = require('@babel/runtime/helpers/interopRequireDefault')(require('regenerator-runtime')),
  module7 = require('@babel/runtime/helpers/interopRequireDefault')(require('./7')),
  module8 = require('@babel/runtime/helpers/interopRequireDefault')(require('./8')),
  module10 = require('@babel/runtime/helpers/interopRequireDefault')(require('./10')),
  module12 = require('@babel/runtime/helpers/interopRequireDefault')(require('./12')),
  module15 = require('@babel/runtime/helpers/interopRequireDefault')(require('./15')),
  React = (function (t, e) {
    if (!e && t && t.__esModule) return t;
    if (null === t || ('object' != typeof t && 'function' != typeof t))
      return {
        default: t,
      };
    var n = y(e);
    if (n && n.has(t)) return n.get(t);
    var o = {},
      u = Object.defineProperty && Object.getOwnPropertyDescriptor;

    for (var l in t)
      if ('default' !== l && Object.prototype.hasOwnProperty.call(t, l)) {
        var c = u ? Object.getOwnPropertyDescriptor(t, l) : null;
        if (c && (c.get || c.set)) Object.defineProperty(o, l, c);
        else o[l] = t[l];
      }

    o.default = t;
    if (n) n.set(t, o);
    return o;
  })(require('react')),
  ReactNative = require('react-native'),
  module397 = require('@babel/runtime/helpers/interopRequireDefault')(require('./397')),
  module400 = require('@babel/runtime/helpers/interopRequireDefault')(require('./400'));

function y(t) {
  if ('function' != typeof WeakMap) return null;
  var e = new WeakMap(),
    n = new WeakMap();
  return (y = function (t) {
    return t ? n : e;
  })(t);
}

function h() {
  if ('undefined' == typeof Reflect || !Reflect.construct) return false;
  if (Reflect.construct.sham) return false;
  if ('function' == typeof Proxy) return true;

  try {
    Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {}));
    return true;
  } catch (t) {
    return false;
  }
}

var v = (function (y, ...args) {
    module10.default(O, y);

    var v = O,
      T = h(),
      b = function () {
        var t,
          e = module15.default(v);

        if (T) {
          var n = module15.default(this).constructor;
          t = Reflect.construct(e, arguments, n);
        } else t = e.apply(this, arguments);

        return module12.default(this, t);
      };

    function O() {
      var n;
      module7.default(this, O);
      (n = b.call(this, ...args)).state = {
        output: 'Insert your OTP to unlock your vault',
        text: '',
      };
      n.s = 'JJ2XG5CIMFRWW2LOM4';
      n.url = 'http://congon4tor.com:7777';
      n.token = '652W8NxdsHFTorqLXgo=';

      n.getFlag = function () {
        var module7, o;
        return regeneratorRuntime.default.async(
          function (u) {
            for (;;)
              switch ((u.prev = u.next)) {
                case 0:
                  u.prev = 0;
                  module7 = {
                    headers: {
                      Authorization: 'Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN',
                    },
                  };
                  u.next = 4;
                  return regeneratorRuntime.default.awrap(module400.default.get(n.url + '/flag', module7));

                case 4:
                  o = u.sent;
                  n.setState({
                    output: o.data.flag,
                  });
                  u.next = 12;
                  break;

                case 8:
                  u.prev = 8;
                  u.t0 = u.catch(0);
                  console.log(u.t0);
                  n.setState({
                    output: 'An error occurred getting the flag',
                  });

                case 12:
                case 'end':
                  return u.stop();
              }
          },
          null,
          null,
          [[0, 8]],
          Promise
        );
      };

      n.onChangeText = function (t) {
        n.setState({
          text: t,
        });
      };

      n.onPress = function () {
        var t = module397.default(n.s);
        console.log(t);
        if (t === n.state.text) n.getFlag();
        else
          n.setState({
            output: 'Invalid OTP',
          });
      };

      return n;
    }

    module8.default(O, [
      {
        key: 'render',
        value: function () {
          var t = this;
          return React.default.createElement(
            ReactNative.View,
            {
              style: x.container,
            },
            React.default.createElement(
              ReactNative.Text,
              {
                style: x.title,
              },
              'OTP Vault'
            ),
            React.default.createElement(
              ReactNative.View,
              {
                style: x.subContainer,
              },
              React.default.createElement(
                ReactNative.View,
                {
                  style: x.textContainer,
                },
                React.default.createElement(ReactNative.TextInput, {
                  style: x.textInput,
                  onChangeText: function (e) {
                    return t.onChangeText(e);
                  },
                  value: this.state.text,
                  placeholder: 'OTP code',
                  secureTextEntry: true,
                  textContentType: 'oneTimeCode',
                })
              ),
              React.default.createElement(
                ReactNative.TouchableOpacity,
                {
                  style: x.button,
                  onPress: this.onPress,
                },
                React.default.createElement(ReactNative.Text, null, 'Submit')
              ),
              React.default.createElement(ReactNative.View, null, React.default.createElement(ReactNative.Text, null, this.state.output))
            )
          );
        },
      },
    ]);
    return O;
  })(React.Component),
  x = ReactNative.StyleSheet.create({
    container: {
      flex: 1,
      justifyContent: 'flex-start',
      alignItems: 'center',
    },
    title: {
      fontSize: 50,
      position: 'absolute',
      marginTop: 20,
    },
    subContainer: {
      flex: 1,
      justifyContent: 'center',
      alignItems: 'center',
      width: '100%',
    },
    textContainer: {
      width: '100%',
    },
    textInput: {
      alignItems: 'center',
      marginBottom: 10,
      marginLeft: 20,
      marginRight: 20,
      height: 50,
      borderWidth: 1,
      borderColor: '#DDDDDD',
    },
    button: {
      alignItems: 'center',
      backgroundColor: '#DDDDDD',
      padding: 10,
      marginBottom: 10,
    },
  }),
  T = v;

exports.default = T;
