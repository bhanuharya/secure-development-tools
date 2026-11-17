import axios from 'axios';

const apiUrl = '/api/accounts';

export function changePassword(accountId: string, body: object) {
  return axios.post(`${apiUrl}/${accountId}/change-password`, body);
}

export function updateEmail(accountId: string, body: object) {
  return axios.put(`${apiUrl}/${accountId}/email`, body);
}
