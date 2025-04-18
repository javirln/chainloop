// Code generated by protoc-gen-go-errors. DO NOT EDIT.

package v1

import (
	fmt "fmt"
	errors "github.com/go-kratos/kratos/v2/errors"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the kratos package it is being compiled against.
const _ = errors.SupportPackageIsVersion1

func IsAllowListErrorUnspecified(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == AllowListError_ALLOW_LIST_ERROR_UNSPECIFIED.String() && e.Code == 500
}

func ErrorAllowListErrorUnspecified(format string, args ...interface{}) *errors.Error {
	return errors.New(500, AllowListError_ALLOW_LIST_ERROR_UNSPECIFIED.String(), fmt.Sprintf(format, args...))
}

func IsAllowListErrorNotInList(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == AllowListError_ALLOW_LIST_ERROR_NOT_IN_LIST.String() && e.Code == 403
}

func ErrorAllowListErrorNotInList(format string, args ...interface{}) *errors.Error {
	return errors.New(403, AllowListError_ALLOW_LIST_ERROR_NOT_IN_LIST.String(), fmt.Sprintf(format, args...))
}

func IsFederatedAuthErrorUnspecified(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == FederatedAuthError_FEDERATED_AUTH_ERROR_UNSPECIFIED.String() && e.Code == 500
}

func ErrorFederatedAuthErrorUnspecified(format string, args ...interface{}) *errors.Error {
	return errors.New(500, FederatedAuthError_FEDERATED_AUTH_ERROR_UNSPECIFIED.String(), fmt.Sprintf(format, args...))
}

func IsFederatedAuthErrorUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == FederatedAuthError_FEDERATED_AUTH_ERROR_UNAUTHORIZED.String() && e.Code == 403
}

func ErrorFederatedAuthErrorUnauthorized(format string, args ...interface{}) *errors.Error {
	return errors.New(403, FederatedAuthError_FEDERATED_AUTH_ERROR_UNAUTHORIZED.String(), fmt.Sprintf(format, args...))
}

func IsUserWithNoMembershipErrorUnspecified(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == UserWithNoMembershipError_USER_WITH_NO_MEMBERSHIP_ERROR_UNSPECIFIED.String() && e.Code == 500
}

func ErrorUserWithNoMembershipErrorUnspecified(format string, args ...interface{}) *errors.Error {
	return errors.New(500, UserWithNoMembershipError_USER_WITH_NO_MEMBERSHIP_ERROR_UNSPECIFIED.String(), fmt.Sprintf(format, args...))
}

func IsUserWithNoMembershipErrorNotInOrg(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == UserWithNoMembershipError_USER_WITH_NO_MEMBERSHIP_ERROR_NOT_IN_ORG.String() && e.Code == 403
}

func ErrorUserWithNoMembershipErrorNotInOrg(format string, args ...interface{}) *errors.Error {
	return errors.New(403, UserWithNoMembershipError_USER_WITH_NO_MEMBERSHIP_ERROR_NOT_IN_ORG.String(), fmt.Sprintf(format, args...))
}

func IsUserNotMemberOfOrgErrorUnspecified(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == UserNotMemberOfOrgError_USER_NOT_MEMBER_OF_ORG_ERROR_UNSPECIFIED.String() && e.Code == 500
}

func ErrorUserNotMemberOfOrgErrorUnspecified(format string, args ...interface{}) *errors.Error {
	return errors.New(500, UserNotMemberOfOrgError_USER_NOT_MEMBER_OF_ORG_ERROR_UNSPECIFIED.String(), fmt.Sprintf(format, args...))
}

func IsUserNotMemberOfOrgErrorNotInOrg(err error) bool {
	if err == nil {
		return false
	}
	e := errors.FromError(err)
	return e.Reason == UserNotMemberOfOrgError_USER_NOT_MEMBER_OF_ORG_ERROR_NOT_IN_ORG.String() && e.Code == 403
}

func ErrorUserNotMemberOfOrgErrorNotInOrg(format string, args ...interface{}) *errors.Error {
	return errors.New(403, UserNotMemberOfOrgError_USER_NOT_MEMBER_OF_ORG_ERROR_NOT_IN_ORG.String(), fmt.Sprintf(format, args...))
}
