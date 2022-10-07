import React from 'react';
import PropTypes from 'prop-types';
import { ProgressAnimation } from '../UtilComponents/ProgressAnimation';
import {Setup2Fa} from './Setup2Fa';
import { config } from '../../types/Config';
import { registerSecurityKey } from '../../util/auth/webauthn';

import {connect} from 'react-redux';
import {bindActionCreators} from 'redux';

import {createDatabaseProviderGenesisUser, createPandaProviderGenesisUser} from '../../actions/users/createGenesisUser';

export class CreateGenesisUserUnconnected extends React.Component {
    static propTypes = {
        config: config,
        createDatabaseUser: PropTypes.func.isRequired,
        createPandaUser: PropTypes.func.isRequired,
        errors: PropTypes.arrayOf(PropTypes.string).isRequired,
        requesting: PropTypes.bool.isRequired,
        totpSecret: PropTypes.string
    };

    state = {
        hasCompletedPhase1: false,
        username: 'admin',
        displayName: 'Administrator',
        password: '',
        confirmPassword: '',
        creatingUser: false,
        tfaCode: ''
    };

    updateState = (e) => {
        this.setState({[e.target.name]: e.target.value});
    };

    canContinue = () => {
        return this.state.username &&
        this.state.displayName &&
        this.state.password &&
        this.state.confirmPassword &&
        this.errors().length === 0 &&
        !this.props.requesting;
    };

    canFinish = () => {
        return this.canContinue() && this.state.tfaCode;
    };

    errors = () => {
        let errors = [];
        const mismatch = this.state.password !== this.state.confirmPassword;
        const passwordTooShort = this.state.password.length < this.props.config.authConfig.minPasswordLength;
        if (mismatch) errors.push('Passwords do not match');
        if (passwordTooShort) errors.push(`Password is too short (minimum ${this.props.config.authConfig.minPasswordLength} characters)`);

        if (this.state.hasCompletedPhase1 && !this.state.tfaCode) {
            errors.push('Enter code');
        }

        return errors;
    }

    submitDatabase = (tfa) => {
        if (!this.state.hasCompletedPhase1 && this.canContinue()) {
            this.setState({hasCompletedPhase1: true});

        } else if (this.state.hasCompletedPhase1 && (this.canFinish() || tfa.type === 'webauthn')) {
            this.props.createDatabaseUser(this.state.username, this.state.displayName, this.state.password, tfa);
        }
    };

    submitPanda = (e) => {
        e.preventDefault();
        this.props.createPandaUser(this.state.username);
    };

    skip2fa = () => {
        this.props.createDatabaseUser(this.state.username, this.state.displayName, this.state.password, undefined);
    };

    totpUrl = () => {
        const totpIssuer = this.props.config.authConfig.totpIssuer;
        const instance = this.props.config.label || window.location.hostname;

        return `otpauth://totp/${this.state.username}?secret=${this.props.totpSecret}&issuer=${totpIssuer}%20(${instance})`;
    }

    renderActions = () => {
        const errors = [].concat(this.errors(), this.props.errors);

        let progress = <span className='error'>
            <strong>{errors.join(', ')}</strong>
        </span>;

        if(this.props.requesting) {
            progress = <ProgressAnimation />;
        }

        const enabled = this.state.hasCompletedPhase1 ? this.canFinish() : this.canContinue();
        const buttonText = this.state.hasCompletedPhase1 ? 'Finish' : 'Continue';

        return <div className='form__actions'>
            <button className='btn' type='submit' disabled={!enabled}>
                {buttonText}
            </button>
            {progress}
        </div>;
    }

    renderField = (name, label, type = 'text', autofocus = false) => {
        return (
            <div className='form__row'>
                <label className='form__label' htmlFor={'#' + name}>{label}</label>
                    <input
                        id={name} className='form__field' autoFocus={autofocus}
                        type={type} name={name} placeholder={label}
                        value={this.state[name]} onChange={this.updateState}
                        autoComplete='off' required />
            </div>
        );
    }

    renderUsernameAndPassword() {
        return (
            <div className='app__page app__page--centered'>
                <form className='form' onSubmit={this.onSubmit}>
                    <h2>Create Genesis User</h2>
                    {this.renderField('username', 'Username', 'text', true)}
                    {this.renderField('displayName', 'Display Name')}
                    {this.renderField('password', 'Password', 'password')}
                    {this.renderField('confirmPassword', 'Confirm Password', 'password')}
                    {this.renderActions()}
                </form>
            </div>
        );
    }

    registerSecurityKey = (e) => {
        e.preventDefault();

        const totpIssuer = this.props.config.authConfig.totpIssuer;
        const instance = this.props.config.label || window.location.hostname;
        const name = `${totpIssuer} (${instance})`;

        registerSecurityKey(this.props.webAuthnChallenge, name, this.props.webAuthnUserHandle, this.state.username, this.state.displayName)
            .then(registration => {
                this.submitDatabase({
                    type: 'webauthn',
                    ...registration
                });
            });
    }

    onSubmit = (e) => {
        e.preventDefault();

        this.submitDatabase({
            type: 'totp',
            secret: this.props.totpSecret,
            code: this.state.tfaCode
        });
    }

    render2FA() {
        return (
            <div className='app__page app__page--centered'>
                <form className='form' noValidate onSubmit={this.onSubmit}>
                    <h2>Setup Two Factor Authentication</h2>
                    <div className='form__section'>
                        <h3 className='form__subtitle'>Authenticator App</h3>
                        <Setup2Fa
                            username={this.state.username}
                            secret={this.props.totpSecret}
                            url={this.totpUrl()}
                            />
                        {this.renderField('tfaCode', 'Authentication Code', 'text', true)}
                        {this.renderActions()}
                    </div>
                    <div className='form__section'>
                        <h3 className='form__subtitle'>Security Key</h3>
                        <button className='btn' onClick={this.registerSecurityKey}>Register</button>
                    </div>
                    {
                        this.props.config.authConfig.require2FA
                        ?
                            false
                        :
                            <div className='form__section'>
                                <button className='users__skip-2fa' type='button' onClick={this.skip2fa}>Skip this step</button>
                            </div>
                    }
                </form>
            </div>
        );
    }

    renderDatabaseProviderGenesis() {
        if (!this.state.hasCompletedPhase1) {
            return this.renderUsernameAndPassword();
        } else {
            return this.render2FA();
        }
    }

    renderPanDomainProviderGenesis() {
        const errors = [].concat(this.errors(), this.props.errors);

        let progress = <span className='error'>
            <strong>{errors.join(', ')}</strong>
        </span>;

        if(this.props.requesting) {
            progress = <ProgressAnimation />;
        }

        const enabled = this.state.username.includes('@') && errors.length === 0 && !this.props.requesting;

        return (
            <div className='app__page app__page--centered'>
                <form className='form' onSubmit={this.submitPanda}>
                    <h2>Create Genesis User</h2>
                    {this.renderField('username', 'E-mail', 'text', true)}

                    <div className='form__actions'>
                    <button className='btn' type='submit' disabled={!enabled}>
                        Finish
                    </button>
                    {progress}
                </div>
                </form>
            </div>
        );
    }

    render() {
        if (!this.props.config) {
            return false;
        }

        if (this.props.config.userProvider === 'database') {
            return this.renderDatabaseProviderGenesis();
        } else if (this.props.config.userProvider === 'panda') {
            return this.renderPanDomainProviderGenesis();
        }
    }
}

function mapStateToProps(state) {
    const users = state.users;

    return {
        config: state.app.config,
        requesting: users.genesisSetupRequesting,
        errors: users.errors,
        totpSecret: users.genesisTotpSecret,
        webAuthnChallenge: users.genesisWebauthnChallenge,
        webAuthnUserHandle: users.genesisWebAuthnUserHandle
    };
}

function mapDispatchToProps(dispatch) {
    return {
        createDatabaseUser: bindActionCreators(createDatabaseProviderGenesisUser, dispatch),
        createPandaUser: bindActionCreators(createPandaProviderGenesisUser, dispatch)
    };
}

export const CreateGenesisUser = connect(mapStateToProps, mapDispatchToProps)(CreateGenesisUserUnconnected);
