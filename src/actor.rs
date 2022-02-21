use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use crate::details;
use crate::policy::PolicyPrincipal;
#[cfg(feature = "service")]
use crate::validate_region;
use crate::{validate_identifier, PrincipalError};

/// Information about a temporary token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// The time that the token was issued, in seconds from the Unix epoch. This provides the
    /// \${aws:TokenIssueTime} Aspen policy variable.
    pub token_issue_time: u64,

    /// The time that the token will expire, in seconds from the Unix epoch.
    pub token_expire_time: u64,
}

pub type AssumedRoleDetails = details::AssumedRoleDetails<TokenInfo>;
pub type FederatedUserDetails = details::FederatedUserDetails<TokenInfo>;
pub type GroupDetails = details::GroupDetails<String>;
pub type InstanceProfileDetails = details::InstanceProfileDetails<String>;
pub type RoleDetails = details::RoleDetails<String>;
pub type RootUserDetails = details::RootUserDetails;
#[cfg(feature = "service")]
pub type ServiceDetails = details::ServiceDetails<Option<String>>;
pub type UserDetails = details::UserDetails<String>;

/// An active, identified AWS principal -- an actor who is making requests against a service.
///
/// In addition to the ARN, an IAM principal actor also has a unique id that changes whenever the principal is
/// recreated. This is in contrast to a PolicyPrincipal, which lacks this id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalActor {
    /// Details for an assumed role.
    AssumedRole(AssumedRoleDetails),

    /// Details for a federated user.
    FederatedUser(FederatedUserDetails),

    /// Details for an IAM group.
    Group(GroupDetails),

    /// Details for an instance profile.
    InstanceProfile(InstanceProfileDetails),

    /// Details for an IAM role.
    Role(RoleDetails),

    /// Details for the root user of an account.
    RootUser(RootUserDetails),

    // #[doc(cfg(feature = "service"))]
    #[cfg(feature = "service")]
    /// Details for a service.
    Service(ServiceDetails),

    /// Details for an IAM user.
    User(UserDetails),
}

impl PrincipalActor {
    /// Return a principal for an assumed role.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///     [PrincipalError::InvalidSessionName] error will be returned:
    ///     *   The session name must contain between 2 and 64 characters.
    ///     *   The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `token_issue_time`: The time in seconds since the Unix epoch when the token was issued.
    /// * `token_expire_time`: the time in seconds since the Unix epoch when the token will become invalid.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [AssumedRoleDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn assumed_role<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        role_name: S3,
        session_name: S4,
        token_issue_time: u64,
        token_expire_time: u64,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self::AssumedRole(AssumedRoleDetails::new(
            partition,
            account_id,
            role_name,
            session_name,
            TokenInfo {
                token_issue_time,
                token_expire_time,
            },
        )?))
    }

    /// Return a principal for a federated user.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidFederatedUserName] error will be returned:
    ///     *   The name must contain between 2 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `token_issue_time`: The time in seconds since the Unix epoch when the token was issued.
    /// * `token_expire_time`: the time in seconds since the Unix epoch when the token will become invalid.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [FederatedUserDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn federated_user<S1, S2, S3>(
        partition: S1,
        account_id: S2,
        user_name: S3,
        token_issue_time: u64,
        token_expire_time: u64,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Ok(Self::FederatedUser(FederatedUserDetails::new(
            partition,
            account_id,
            user_name,
            TokenInfo {
                token_issue_time,
                token_expire_time,
            },
        )?))
    }

    /// Return a principal for a group.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `group_name`: The name of the group. This must meet the following requirements or a
    ///     [PrincipalError::InvalidGroupName] error will be returned:
    ///     *   The name must contain between 1 and 128 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `group_id`: The universally-unique identifier for the group. This must be a 20 character base-32 string
    ///     starting with `AGPA` or a [PrincipalError::InvalidGroupId] error will be returned.
    ///
    /// # Return value
    /// If all of the requirements are met, a [PrincipalActor] with [GroupDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn group<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        group_name: S4,
        group_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self::Group(GroupDetails::new(
            partition,
            account_id,
            path,
            group_name,
            validate_identifier(group_id, "AGPA").map_err(PrincipalError::InvalidGroupId)?,
        )?))
    }

    /// Return a principal for an instance profile.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `instance_profile_name`: The name of the instance profile. This must meet the following requirements or a
    ///     [PrincipalError::InvalidInstanceProfileName] error will be returned:
    ///     *   The name must contain between 1 and 128 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `instance_profile_id`: The universally-unique identifier for the instance profile. This must be a 20 character
    ///     base-32 string starting `AIPA` or a [PrincipalError::InvalidInstanceProfileId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [InstanceProfileDetails] details is returned.
    /// Otherwise, a [PrincipalError] error is returned.
    pub fn instance_profile<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        instance_profile_name: S4,
        instance_profile_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self::InstanceProfile(InstanceProfileDetails::new(
            partition,
            account_id,
            path,
            instance_profile_name,
            validate_identifier(instance_profile_id, "AIPA").map_err(PrincipalError::InvalidInstanceProfileId)?,
        )?))
    }

    /// Return a principal for a role.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `role_name`: The name of the role. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `role_id`: The universally-unique identifier for the role. This must be a 20 character
    ///     base-32 string starting with `AROA` or a [PrincipalError::InvalidRoleId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [RoleDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn role<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        role_name: S4,
        role_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self::Role(RoleDetails::new(
            partition,
            account_id,
            path,
            role_name,
            validate_identifier(role_id, "AROA").map_err(PrincipalError::InvalidRoleId)?,
        )?))
    }

    /// Return a principal for the root user of an account.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [RootUserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn root_user<S1, S2>(partition: S1, account_id: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self::RootUser(RootUserDetails::new(Some(partition.into()), account_id)?))
    }

    #[cfg(feature = "service")]
    // #[doc(cfg(feature = "service"))]
    /// Return a principal for a service.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `region`: The region the service is operating in, or `None` if the service is a global service. If specified,
    ///     this must be a valid region in one of the following formats:
    ///     * <code>( <i>name</i> - )+ <i>digit</i>+</code>: e.g., test-10, us-west-2, us-test-site-30
    ///     * <code>( <i>name</i> - )+ <i>digit</i>+ - ( <i>name</i> - )+ <i>digit</i>+</code>: e.g., us-west-2-lax-1
    ///     * The literal string `local`.
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidServiceName] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [ServiceDetails] details is returned.  Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn service<S1, S2>(partition: S1, service_name: S2, region: Option<String>) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let region = match region {
            None => None,
            Some(region) => Some(validate_region(region)?),
        };

        Ok(Self::Service(ServiceDetails::new(Some(partition.into()), service_name, region)?))
    }

    /// Return a principal for a user.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `user_name`: The name of the user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidUserName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `user_id`: The universally-unique identifier for the user. This must be a 20 character
    ///     base-32 string starting with `AIDA` or a [PrincipalError::InvalidUserId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [UserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn user<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        user_name: S4,
        user_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self::User(UserDetails::new(
            partition,
            account_id,
            path,
            user_name,
            validate_identifier(user_id, "AIDA").map_err(PrincipalError::InvalidUserId)?,
        )?))
    }
}

impl Display for PrincipalActor {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AssumedRole(ref d) => {
                write!(f, "arn:{}:sts::{}:assumed-role/{}/{}", d.partition, d.account_id, d.role_name, d.session_name)
            }
            Self::FederatedUser(ref d) => {
                write!(f, "arn:{}:sts::{}:federated-user/{}", d.partition, d.account_id, d.user_name)
            }
            Self::InstanceProfile(ref d) => write!(
                f,
                "arn:{}:iam::{}:instance-profile{}{}",
                d.partition, d.account_id, d.path, d.instance_profile_name
            ),
            Self::Group(ref d) => {
                write!(f, "arn:{}:iam::{}:group{}{}", d.partition, d.account_id, d.path, d.group_name)
            }
            Self::Role(ref d) => write!(f, "arn:{}:iam::{}:role{}{}", d.partition, d.account_id, d.path, d.role_name),
            Self::RootUser(ref d) => match &d.partition {
                None => write!(f, "{}", d.account_id),
                Some(partition) => write!(f, "arn:{}:iam::{}:root", partition, d.account_id),
            },
            Self::User(ref d) => write!(f, "arn:{}:iam::{}:user{}{}", d.partition, d.account_id, d.path, d.user_name),
            #[cfg(feature = "service")]
            Self::Service(ref s) => match (&s.partition, &s.data) {
                (Some(partition), Some(region)) => {
                    write!(f, "arn:{}:iam:{}::service/{}", partition, region, s.service_name)
                }
                _ => write!(f, "{}", s.service_name),
            },
        }
    }
}

impl From<PrincipalActor> for PolicyPrincipal {
    /// Convert the PrincipalActor into a PolicyPrincipal.
    ///
    /// This is a lossy conversion, losing the identifier or token details attached to the actor.
    fn from(from: PrincipalActor) -> PolicyPrincipal {
        match from {
            PrincipalActor::AssumedRole(d) => PolicyPrincipal::AssumedRole(d.into()),
            PrincipalActor::FederatedUser(d) => PolicyPrincipal::FederatedUser(d.into()),
            PrincipalActor::Group(d) => PolicyPrincipal::Group(d.into()),
            PrincipalActor::InstanceProfile(d) => PolicyPrincipal::InstanceProfile(d.into()),
            PrincipalActor::Role(d) => PolicyPrincipal::Role(d.into()),
            PrincipalActor::RootUser(d) => PolicyPrincipal::RootUser(d),
            #[cfg(feature = "service")]
            PrincipalActor::Service(d) => PolicyPrincipal::Service(d.into()),
            PrincipalActor::User(d) => PolicyPrincipal::User(d.into()),
        }
    }
}

impl From<AssumedRoleDetails> for details::AssumedRoleDetails<()> {
    fn from(from: AssumedRoleDetails) -> details::AssumedRoleDetails<()> {
        details::AssumedRoleDetails {
            partition: from.partition,
            account_id: from.account_id,
            role_name: from.role_name,
            session_name: from.session_name,
            data: (),
        }
    }
}

impl From<FederatedUserDetails> for details::FederatedUserDetails<()> {
    fn from(from: FederatedUserDetails) -> details::FederatedUserDetails<()> {
        details::FederatedUserDetails {
            partition: from.partition,
            account_id: from.account_id,
            user_name: from.user_name,
            data: (),
        }
    }
}

impl From<GroupDetails> for details::GroupDetails<()> {
    fn from(from: GroupDetails) -> details::GroupDetails<()> {
        details::GroupDetails {
            partition: from.partition,
            account_id: from.account_id,
            path: from.path,
            group_name: from.group_name,
            data: (),
        }
    }
}

impl From<InstanceProfileDetails> for details::InstanceProfileDetails<()> {
    fn from(from: InstanceProfileDetails) -> details::InstanceProfileDetails<()> {
        details::InstanceProfileDetails {
            partition: from.partition,
            account_id: from.account_id,
            path: from.path,
            instance_profile_name: from.instance_profile_name,
            data: (),
        }
    }
}

impl From<RoleDetails> for details::RoleDetails<()> {
    fn from(from: RoleDetails) -> details::RoleDetails<()> {
        details::RoleDetails {
            partition: from.partition,
            account_id: from.account_id,
            path: from.path,
            role_name: from.role_name,
            data: (),
        }
    }
}

#[cfg(feature = "service")]
impl From<ServiceDetails> for details::ServiceDetails<()> {
    fn from(from: ServiceDetails) -> details::ServiceDetails<()> {
        details::ServiceDetails {
            partition: from.partition,
            service_name: from.service_name,
            data: (),
        }
    }
}

impl From<UserDetails> for details::UserDetails<()> {
    fn from(from: UserDetails) -> details::UserDetails<()> {
        details::UserDetails {
            partition: from.partition,
            account_id: from.account_id,
            path: from.path,
            user_name: from.user_name,
            data: (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrincipalActor;

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = PrincipalActor::assumed_role("aws", "123456789012", "Role_name", "session_name", 0, 3600).unwrap();
        let r1b = PrincipalActor::assumed_role("aws", "123456789012", "Role_name", "session_name", 0, 3600).unwrap();
        let r2 = PrincipalActor::assumed_role(
            "a-very-long-partition1",
            "123456789012",
            "Role@Foo=bar,baz_=world-1234",
            "Session@1234,_=-,.OK",
            0,
            3600,
        )
        .unwrap();

        assert!(r1a == r1b);
        assert!(r1a != r2);

        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r1b.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(
            r2.to_string(),
            "arn:a-very-long-partition1:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK");

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        PrincipalActor::assumed_role(
            "partition-with-32-characters1234",
            "123456789012",
            "role-name",
            "session_name",
            0,
            3600,
        )
        .unwrap();
        PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-64-characters====================================",
            "session@1234",
            0,
            3600,
        )
        .unwrap();
        PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-64-characters=================================",
            0,
            3600,
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(
            PrincipalActor::assumed_role("", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "", "role-name", "session-name", 0, 3600).unwrap_err().to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "", "session-name", 0, 3600).unwrap_err().to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "", 0, 3600).unwrap_err().to_string(),
            "Invalid session name: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "s", 0, 3600).unwrap_err().to_string(),
            "Invalid session name: \"s\""
        );

        assert_eq!(
            PrincipalActor::assumed_role(
                "partition-with-33-characters12345",
                "123456789012",
                "role-name",
                "session_name",
                0,
                3600,
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "1234567890123", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert!(PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-65-characters=====================================",
            "session-name",
            0,
            3600,
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid role name: \"role-name-with-65-characters="));
        assert!(PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-65-characters==================================",
            0,
            3600,
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid session name: \"session-name-with-65-characters="));

        assert_eq!(
            PrincipalActor::assumed_role("-aws", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"-aws\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws-", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aws-\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws--us", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aws--us\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aw!", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aw!\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "a23456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"a23456789012\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role+name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"role+name\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "session+name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"session+name\""
        );
    }

    #[test]
    fn check_valid_federated_users() {
        let f1 = PrincipalActor::federated_user("aws", "123456789012", "user@domain", 0, 3600).unwrap();
        assert_eq!(f1.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain");
        assert_eq!(
            PrincipalActor::federated_user("partition-with-32-characters1234", "123456789012", "user@domain", 0, 3600,)
                .unwrap()
                .to_string(),
            "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain"
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "user@domain-with-32-characters==", 0, 3600,)
                .unwrap()
                .to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain-with-32-characters=="
        );

        let f1_clone = f1.clone();
        assert!(f1 == f1_clone);
    }

    #[test]
    fn check_invalid_federated_users() {
        assert_eq!(
            PrincipalActor::federated_user("", "123456789012", "user@domain", 0, 3600).unwrap_err().to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "", "user@domain", 0, 3600).unwrap_err().to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "", 0, 3600).unwrap_err().to_string(),
            "Invalid federated user name: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "u", 0, 3600).unwrap_err().to_string(),
            "Invalid federated user name: \"u\""
        );

        assert_eq!(
            PrincipalActor::federated_user(
                "partition-with-33-characters12345",
                "123456789012",
                "user@domain",
                0,
                3600,
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "1234567890123", "user@domain", 0, 3600).unwrap_err().to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "user@domain-with-33-characters===", 0, 3600,)
                .unwrap_err()
                .to_string(),
            "Invalid federated user name: \"user@domain-with-33-characters===\""
        );
    }

    #[test]
    fn check_valid_groups() {
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path/test/", "group-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/path/test/group-name"
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/path///multi-slash/test/group-name"
        );
        assert_eq!(
            PrincipalActor::group(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name-with-128-characters==================================================================================================", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name-with-128-characters==================================================================================================");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPALMNOPQRSTUVWXY23")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
    }

    #[test]
    fn check_invalid_groups() {
        PrincipalActor::group("", "123456789012", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        PrincipalActor::group("aws", "", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        PrincipalActor::group("aws", "123456789012", "", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid group name: \"\""
        );
        PrincipalActor::group("aws", "123456789012", "/", "group-name", "").unwrap_err();

        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid group id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPA________________")
                .unwrap_err()
                .to_string(),
            "Invalid group id: \"AGPA________________\""
        );
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "path/test/", "group-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path/test", "group-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path test/", "group-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name"
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/path/test/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/path/test/instance-profile-name"
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/path///multi-slash/test/instance-profile-name"
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/instance-profile-name");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name-with-128-characters=======================================================================================", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name-with-128-characters=======================================================================================");
        PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "AIPALMNOPQRSTUVWXY23")
            .unwrap();
    }

    #[test]
    fn check_invalid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile("", "123456789012", "/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile("aws", "", "/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "", "AIPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid instance profile name: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "")
                .unwrap_err()
                .to_string(),
            "Invalid instance profile id: \"\""
        );

        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIPA________________"
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile id: \"AIPA________________\""
        );
    }

    #[test]
    fn check_valid_roles() {
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/role-name"
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path/test/", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:role/path/test/role-name"
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/path///multi-slash/test/role-name"
        );
        assert_eq!(
            PrincipalActor::role(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/role-name");
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/",
                "role-name-with-64-characters====================================",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/role-name-with-64-characters===================================="
        );
        PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROALMNOPQRSTUVWXY23").unwrap();
    }

    #[test]
    fn check_invalid_roles() {
        assert_eq!(
            PrincipalActor::role("", "123456789012", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "").unwrap_err().to_string(),
            "Invalid role id: \"\""
        );

        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid role id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROA________________")
                .unwrap_err()
                .to_string(),
            "Invalid role id: \"AROA________________\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "path/test/", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path/test", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path test/", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/",
                "role-name-with-65-characters=====================================",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid role name: \"role-name-with-65-characters=====================================\""
        );
    }

    #[test]
    fn check_valid_root_users() {
        assert_eq!(
            PrincipalActor::root_user("aws", "123456789012").unwrap().to_string(),
            "arn:aws:iam::123456789012:root"
        );
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(PrincipalActor::root_user("", "123456789012").unwrap_err().to_string(), "Invalid partition: \"\"");
        assert_eq!(PrincipalActor::root_user("aws", "").unwrap_err().to_string(), "Invalid account id: \"\"");
    }

    #[test]
    fn check_valid_users() {
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:user/user-name"
        );
        PrincipalActor::user("aws", "123456789012", "/path/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user("aws", "123456789012", "/path///multi-slash/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK")
            .unwrap();
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
            "user-name",
            "AIDAA2B3C4D5E6F7HIJK",
        )
        .unwrap();
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/",
            "user-name-with-64-characters====================================",
            "AIDAA2B3C4D5E6F7HIJK",
        )
        .unwrap();
        PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDALMNOPQRSTUVWXY23").unwrap();
    }

    #[test]
    fn check_invalid_users() {
        assert_eq!(
            PrincipalActor::user("", "123456789012", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid user name: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "").unwrap_err().to_string(),
            "Invalid user id: \"\""
        );

        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid user id: \"AGPAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDA________________")
                .unwrap_err()
                .to_string(),
            "Invalid user id: \"AIDA________________\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "path/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/path/test", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/path test/", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_services() {
        assert_eq!(PrincipalActor::service("aws", "service-name", None).unwrap().to_string(), "service-name");
        assert_eq!(
            PrincipalActor::service("aws", "service-name", Some("us-east-1".to_string())).unwrap().to_string(),
            "arn:aws:iam:us-east-1::service/service-name"
        );
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            PrincipalActor::service("aws", "service name", None).unwrap_err().to_string(),
            "Invalid service name: \"service name\""
        );
    }
}
