
const { Strategy } = require('passport-local')
const { toLower } = require('lodash/fp')
const ldap = require('ldapjs');
const addressConstant = 'cn=commonName,dc=domainComponent,dc=lastDomainComponent'

const ldapSearch = (baseDN, options, client) => {
  return new Promise((resolve, reject) => {
    client.search(baseDN, options, (err, res) => {

      if (err) {
        return reject(err)
      }

      res.on('searchEntry', (entry) => {
        return resolve(entry.object)
      })

      res.on('error', (err) => {
        console.error('error: ' + err.message)
        return reject(err)
      })
    })
  })
}

function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}


module.exports = ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET'),
    providers: [
      {
        uid: 'customPassport',
        displayName: 'customPassport',
        createStrategy: (strapi) => new Strategy(
          {
            usernameField: 'email',
            passwordField: 'password',
            session: false,
          },
          async (email, password, done) => {
            const client = ldap.createClient({
              url: ['ldap://18.136.205.62:389']
            });

            client.on('error', (err) => {
              // handle connection error
              console.log('Error Connection:', err);
            })

            let [commonName, domainComponent, lastDomainComponent] = toLower(email).split(/\@|\./)
            const isMatchedUnderScore = user.match('_')?.length > 0
            if (isMatchedUnderScore) {
              const userSplited = user.split('_')
              const fn = capitalizeFirstLetter(userSplited[0])
              const ln = capitalizeFirstLetter(userSplited[1])
              commonName = `${fn} ${ln}`
            }
            const address = addressConstant.replace('commonName', commonName).replace('domainComponent', domainComponent).replace('domainComponent', lastDomainComponent)
            return client.bind(address, password, async (err) => {
              if (err) {
                done(null, false, { message: err?.message })
                client.unbind()
                return
              }

              const opts = {
                scope: 'sub',
                filter: '(&(objectClass=*)(CN=' + commonName + '))',
                attrs: 'memberOf'
              };

              ldapSearch(address, opts, client).then(res => {
                console.log(' >>>>>>>>>>>>>>>>>>>>> res ldap', res);
              }).catch(err => {
                console.log(' >>>>>>>>>>>>>>>>>>>>> err ldap', err);
              })

              //temp
              done(null, {
                id: 1,
                role:'Admin',
                firstname: 'Apisit',
                lastname: 'Amklang'
              })
            })

            // ####### this is default authentication ##########
            // return strapi.admin.services.auth
            //   .checkCredentials({ email: toLower(email), password })
            //   .then(([error, user, message]) => {
            //     console.log('>>>>>>',{ error, user, message });
            //     return done(error, user, message)
            //   })
            //   .catch((error) => {
            //     console.log('>>>>>>> ? error',error);
            //     return done(error)
            //   });
          }
        )
      }
    ],
    events: {
      onConnectionSuccess(e) {
        console.log('>>>>>>>>>>> ======= onConnectionSuccess', e);
      },
      onConnectionError(e) {
        console.log('>>>>>>>>>>> onConnectionError', e);
      },
      onSSOAutoRegistration(e) {
        const { user, provider } = e;

        console.log(
          `A new user (${user.id}) has been automatically registered using ${provider}`
        );
      },
    },
  },
  apiToken: {
    salt: env('API_TOKEN_SALT'),
  },
});
